"""Bluetooth scanning sensor for Windows, driven by PowerShell.

The Windows counterpart of :class:`src.sensors.bluetooth_sensor.BluetoothSensor`.

Primary backend: a live BLE sweep via the WinRT
``BluetoothLEAdvertisementWatcher`` (Windows 10+), driven from PowerShell. This
is a true passive/active RF scan — it reports every advertising device in
range with its real RSSI, which is what the proximity and tracker rules want.

Fallback backend: ``Get-PnpDevice -Class Bluetooth -PresentOnly`` enumerates
the devices the OS stack already knows (paired/connected classic + BLE). It has
no RSSI, but it still surfaces devices when the advertisement watcher is
unavailable (older Windows, no BLE radio, group policy).

Both backends map into the same reading schema the detection engine consumes —
``devices`` with ``address``/``name``/``rssi`` keys — so Bluetooth rules,
enrichment, and correlation work unchanged. The PowerShell here cannot be
exercised off-Windows, so the JSON parsing is factored into pure static methods
that are unit-tested directly.
"""

import json
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from src.sensors.base_sensor import BaseSensor
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Bluetooth device addresses show up in a PnP InstanceId as "Dev_AABBCCDDEEFF"
# (classic) or a bare 12-hex run inside the BTHLE path (low energy).
_DEV_ADDR_RE = re.compile(r"[Dd]ev_([0-9A-Fa-f]{12})")
_BARE_ADDR_RE = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{12})(?![0-9A-Fa-f])")

# Live BLE sweep: start a WinRT advertisement watcher, collect every
# advertisement seen during the scan window into a synchronized hashtable
# (populated from the event handler via -MessageData, the scope-safe pattern),
# then emit address/name/rssi as JSON. __SECONDS__ is substituted with the
# scan window; addresses come back as lowercase colon-separated MACs.
_BLE_WATCHER_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$null = [Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher, Windows, ContentType=WindowsRuntime]
$watcher = [Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher]::new()
$watcher.ScanningMode = 'Active'
$seen = [hashtable]::Synchronized(@{})
$sub = Register-ObjectEvent -InputObject $watcher -EventName Received -MessageData $seen -Action {
    $store = $Event.MessageData
    $args0 = $Event.SourceEventArgs
    $mac = (('{0:X12}' -f $args0.BluetoothAddress) -replace '(..)(?!$)', '$1:').ToLower()
    $store[$mac] = [pscustomobject]@{
        address = $mac
        name    = $args0.Advertisement.LocalName
        rssi    = [int]$args0.RawSignalStrengthInDBm
    }
}
$watcher.Start()
Start-Sleep -Seconds __SECONDS__
$watcher.Stop()
Unregister-Event -SourceIdentifier $sub.Name
$out = @($seen.Values)
if ($out.Count -gt 0) { $out | ConvertTo-Json -Compress } else { '[]' }
"""

_PNP_COMMAND = (
    "Get-PnpDevice -Class Bluetooth -PresentOnly | "
    "Select-Object FriendlyName,InstanceId,Status | ConvertTo-Json -Compress"
)


def _format_mac(hex12: str) -> str:
    """Format 12 hex characters as a lowercase colon-separated MAC address."""
    h = hex12.lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def _address_from_instance_id(instance_id: str) -> Optional[str]:
    """Extract a Bluetooth MAC from a PnP InstanceId, or None if absent."""
    if not instance_id:
        return None
    m = _DEV_ADDR_RE.search(instance_id)
    if m:
        return _format_mac(m.group(1))
    m = _BARE_ADDR_RE.search(instance_id.replace(":", ""))
    if m:
        return _format_mac(m.group(1))
    return None


class WindowsBluetoothSensor(BaseSensor):
    """Scans Bluetooth via a WinRT BLE watcher (PnP fallback) and tracks new devices."""

    def __init__(self, sensor_id: str, config: dict):
        super().__init__(sensor_id, "bluetooth", config)
        self._interval = config.get("scan_interval", 30)
        self._scan_seconds = max(1, int(config.get("ble_scan_seconds", 4)))
        self._pnp_fallback = bool(config.get("pnp_fallback", True))
        self._known_file = Path(config.get("known_devices_file", "data/known_bt_devices.txt"))
        self._known_addrs: set = self._load_known()
        self._thread: Optional[threading.Thread] = None

    def _load_known(self) -> set:
        """Load previously-seen device addresses from disk."""
        if not self._known_file.exists():
            return set()
        return {line.strip() for line in self._known_file.read_text().splitlines() if line.strip()}

    def _save_known(self):
        """Persist the set of known device addresses to disk."""
        self._known_file.parent.mkdir(exist_ok=True, parents=True)
        self._known_file.write_text("\n".join(sorted(self._known_addrs)) + "\n")

    def _shell(self) -> Optional[str]:
        """Return the PowerShell executable to use, or None if unavailable."""
        return shutil.which("powershell") or shutil.which("pwsh")

    def connect(self) -> bool:
        """Check that PowerShell is available; return True on success."""
        if self._shell() is None:
            logger.warning("powershell not found — Windows Bluetooth sensor disabled")
            return False
        self.connected = True
        return True

    def disconnect(self):
        """Stop recording and mark the sensor disconnected."""
        self.stop_recording()  # already persists known devices
        self.connected = False

    def start_recording(self) -> bool:
        """Start the background sampling thread; return True on success."""
        if not self.connected:
            return False
        self.recording = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return True

    def stop_recording(self):
        """Stop the background sampling thread."""
        self.recording = False
        if self._thread:
            self._thread.join(timeout=5)
        self._save_known()

    def _loop(self):
        while self.recording:
            scan = self._scan()
            if scan:
                self.record(scan)
            time.sleep(self._interval)

    @staticmethod
    def parse_advertisements(raw: str) -> List[dict]:
        """Parse the BLE watcher's JSON into devices.

        Returns one dict per unique address with ``address``/``name``/``rssi``.
        ``ConvertTo-Json`` emits a bare object for a single advertisement and an
        array for several; when the same address appears more than once the
        strongest (least-negative) RSSI is kept.
        """
        raw = (raw or "").strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            return []
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return []

        best: dict = {}
        for entry in data:
            if not isinstance(entry, dict):
                continue
            addr = entry.get("address")
            if not addr:
                continue
            addr = str(addr).lower()
            rssi = entry.get("rssi")
            name = entry.get("name") or None
            prev = best.get(addr)
            if prev is None or (rssi is not None and prev.get("rssi") is not None
                                and rssi > prev["rssi"]):
                best[addr] = {"address": addr, "name": name, "rssi": rssi}
            elif prev.get("name") is None and name is not None:
                prev["name"] = name
        return list(best.values())

    @staticmethod
    def parse_devices(raw: str) -> List[dict]:
        """Parse ``Get-PnpDevice ... | ConvertTo-Json`` output into devices.

        Fallback backend. Returns one dict per device with
        ``address``/``name``/``status`` keys (matching the Termux Bluetooth
        schema); devices whose InstanceId carries no resolvable address are
        skipped. Handles both the bare-object and array JSON shapes.
        """
        raw = (raw or "").strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            return []
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return []

        devices: List[dict] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            addr = _address_from_instance_id(entry.get("InstanceId", ""))
            if not addr:
                continue
            devices.append({
                "address": addr,
                "name": entry.get("FriendlyName"),
                "status": entry.get("Status"),
            })
        return devices

    def _run(self, script: str, timeout: float) -> Optional[str]:
        """Run a PowerShell snippet and return stdout, or None on failure."""
        shell = self._shell()
        if not shell:
            return None
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return None
        return result.stdout

    def _collect_devices(self) -> List[dict]:
        """Run the BLE watcher, falling back to PnP enumeration if it finds nothing."""
        try:
            script = _BLE_WATCHER_SCRIPT.replace("__SECONDS__", str(self._scan_seconds))
            out = self._run(script, timeout=self._scan_seconds + 15)
            devices = self.parse_advertisements(out) if out else []
        except Exception as e:
            logger.debug(f"BLE watcher failed, will consider fallback: {e}")
            devices = []

        if devices or not self._pnp_fallback:
            return devices

        try:
            out = self._run(_PNP_COMMAND, timeout=20)
            return self.parse_devices(out) if out else []
        except Exception as e:
            logger.error(f"Windows Bluetooth PnP fallback error: {e}")
            return []

    def _scan(self) -> Optional[dict]:
        """Run one scan and build a reading, or None on failure."""
        try:
            devices = self._collect_devices()
            addrs = {d["address"] for d in devices if d.get("address")}
            new_addrs = addrs - self._known_addrs
            self._known_addrs.update(new_addrs)

            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sensor_id": self.sensor_id,
                "sensor_type": "bluetooth",
                "devices": devices,
                "device_count": len(devices),
                "new_device_count": len(new_addrs),
                "new_devices": list(new_addrs),
            }
        except Exception as e:
            logger.error(f"Windows Bluetooth scan error: {e}")
            return None
