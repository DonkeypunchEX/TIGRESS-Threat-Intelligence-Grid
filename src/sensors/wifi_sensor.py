"""WiFi scanning sensor backed by termux-wifi-scaninfo."""

import json
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from src.sensors.base_sensor import BaseSensor
from src.utils.known_list import load_known, prune_known, save_known
from src.utils.logger import get_logger

logger = get_logger(__name__)


class WiFiSensor(BaseSensor):
    """Polls `termux-wifi-scaninfo` and tracks newly-seen BSSIDs."""

    def __init__(self, sensor_id: str, config: dict):
        super().__init__(sensor_id, "wifi", config)
        self._interval = config.get("scan_interval", 30)
        self._known_file = Path(config.get("known_bssids_file", "data/known_bssids.txt"))
        # address -> last_seen epoch; pruned so a place visited once long ago
        # stops diluting the "new AP" signal forever.
        self._max_age_days = int(config.get("known_max_age_days", 30))
        self._known_bssids: Dict[str, float] = prune_known(
            load_known(self._known_file), self._max_age_days
        )
        self._thread: Optional[threading.Thread] = None

    def _save_known(self):
        self._known_bssids = prune_known(self._known_bssids, self._max_age_days)
        save_known(self._known_file, self._known_bssids)

    def connect(self) -> bool:
        """Check the sensor backend is available; return True on success."""
        result = subprocess.run(["which", "termux-wifi-scaninfo"], capture_output=True)
        if result.returncode != 0:
            logger.warning("termux-wifi-scaninfo not found — WiFi sensor disabled")
            return False
        self.connected = True
        return True

    def disconnect(self):
        """Stop recording and mark the sensor disconnected."""
        self.stop_recording()
        self._save_known()
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

    def _scan(self) -> Optional[dict]:
        try:
            result = subprocess.run(
                ["termux-wifi-scaninfo"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None

            networks = json.loads(result.stdout)
            bssids = {net.get("BSSID", "").lower() for net in networks if net.get("BSSID")}
            now = time.time()
            new_bssids = bssids - set(self._known_bssids)
            for b in bssids:  # refresh last-seen for all, add the new ones
                self._known_bssids[b] = now

            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sensor_id": self.sensor_id,
                "sensor_type": "wifi",
                "networks": networks,
                "ap_count": len(networks),
                "new_ap_count": len(new_bssids),
                "new_bssids": list(new_bssids),
            }
        except Exception as e:
            logger.error(f"WiFi scan error: {e}")
            return None
