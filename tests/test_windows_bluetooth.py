"""Windows Bluetooth sensor: BLE-advertisement + PnP parsing (hermetic)."""

import json

from src.sensors.windows.bluetooth_sensor import (
    WindowsBluetoothSensor,
    _address_from_instance_id,
)

# --------------------------------------------------------------------------- #
# BLE advertisement watcher (primary backend)
# --------------------------------------------------------------------------- #

# Watcher JSON: same address twice (weak then strong), plus a nameless beacon.
BLE_ARRAY = json.dumps([
    {"address": "e0:aa:bb:cc:dd:ee", "name": "AirTag", "rssi": -70},
    {"address": "e0:aa:bb:cc:dd:ee", "name": "AirTag", "rssi": -42},
    {"address": "11:22:33:44:55:66", "name": None, "rssi": -55},
])

# ConvertTo-Json emits a bare object for a single advertisement.
BLE_SINGLE = json.dumps({"address": "aa:bb:cc:dd:ee:ff", "name": "Buds", "rssi": -60})


def test_parse_advertisements_dedupes_keeping_strongest_rssi():
    devs = WindowsBluetoothSensor.parse_advertisements(BLE_ARRAY)
    by_addr = {d["address"]: d for d in devs}
    assert set(by_addr) == {"e0:aa:bb:cc:dd:ee", "11:22:33:44:55:66"}
    # Strongest (least-negative) RSSI wins for a repeated address.
    assert by_addr["e0:aa:bb:cc:dd:ee"]["rssi"] == -42
    assert by_addr["e0:aa:bb:cc:dd:ee"]["name"] == "AirTag"


def test_parse_advertisements_single_object():
    devs = WindowsBluetoothSensor.parse_advertisements(BLE_SINGLE)
    assert len(devs) == 1
    assert devs[0]["address"] == "aa:bb:cc:dd:ee:ff"
    assert devs[0]["rssi"] == -60


def test_parse_advertisements_handles_empty_and_garbage():
    assert WindowsBluetoothSensor.parse_advertisements("") == []
    assert WindowsBluetoothSensor.parse_advertisements("[]") == []
    assert WindowsBluetoothSensor.parse_advertisements("not json") == []


# --------------------------------------------------------------------------- #
# PnP enumeration (fallback backend)
# --------------------------------------------------------------------------- #

PNP_ARRAY = json.dumps([
    {
        "FriendlyName": "AirTag",
        "InstanceId": "BTHLE\\Dev_e0aabbccddee\\8&abc123&0&e0aabbccddee",
        "Status": "OK",
    },
    {
        "FriendlyName": "Wireless Mouse",
        "InstanceId": "BTHENUM\\Dev_A1B2C3D4E5F6\\7&1a2b&0",
        "Status": "OK",
    },
    {
        # A Bluetooth radio/host entry with no device address -> skipped.
        "FriendlyName": "Intel Wireless Bluetooth",
        "InstanceId": "USB\\VID_8087&PID_0026\\5&deadbeef",
        "Status": "OK",
    },
])

PNP_SINGLE = json.dumps({
    "FriendlyName": "Galaxy Buds",
    "InstanceId": "BTHENUM\\Dev_112233445566\\7&x&0",
    "Status": "OK",
})


def test_address_extraction_variants():
    assert _address_from_instance_id("BTHENUM\\Dev_A1B2C3D4E5F6\\7") == "a1:b2:c3:d4:e5:f6"
    assert _address_from_instance_id("BTHLE\\Dev_e0aabbccddee\\8") == "e0:aa:bb:cc:dd:ee"
    assert _address_from_instance_id("USB\\VID_8087&PID_0026") is None
    assert _address_from_instance_id("") is None


def test_parse_devices_array_skips_addressless():
    devs = WindowsBluetoothSensor.parse_devices(PNP_ARRAY)
    addrs = {d["address"] for d in devs}
    assert addrs == {"e0:aa:bb:cc:dd:ee", "a1:b2:c3:d4:e5:f6"}


def test_parse_devices_single_object():
    devs = WindowsBluetoothSensor.parse_devices(PNP_SINGLE)
    assert len(devs) == 1
    assert devs[0]["address"] == "11:22:33:44:55:66"


def test_parse_devices_handles_empty_and_garbage():
    assert WindowsBluetoothSensor.parse_devices("") == []
    assert WindowsBluetoothSensor.parse_devices("not json") == []


# --------------------------------------------------------------------------- #
# Scan orchestration: watcher first, PnP fallback
# --------------------------------------------------------------------------- #

def _make_sensor(tmp_path):
    known = tmp_path / "known_bt.txt"
    return WindowsBluetoothSensor(
        "bluetooth_sensor",
        {"known_devices_file": str(known), "ble_scan_seconds": 1},
    )


def _script_of(call_args):
    # subprocess.run(cmd_list, ...); the PowerShell script is the last token.
    return call_args[0][-1]


def test_scan_prefers_live_ble_advertisements(tmp_path, monkeypatch):
    sensor = _make_sensor(tmp_path)
    seen_scripts = []

    def _fake_run(cmd, **kwargs):
        seen_scripts.append(_script_of((cmd,)))

        class _R:
            returncode = 0
            stdout = BLE_ARRAY
        return _R()

    monkeypatch.setattr(
        "src.sensors.windows.bluetooth_sensor.shutil.which", lambda _c: "powershell"
    )
    monkeypatch.setattr(
        "src.sensors.windows.bluetooth_sensor.subprocess.run", _fake_run
    )

    reading = sensor._scan()
    assert reading["device_count"] == 2
    assert reading["new_device_count"] == 2
    # The BLE watcher was used and the PnP fallback was NOT needed.
    assert any("BluetoothLEAdvertisementWatcher" in s for s in seen_scripts)
    assert not any("Get-PnpDevice" in s for s in seen_scripts)


def test_scan_falls_back_to_pnp_when_watcher_empty(tmp_path, monkeypatch):
    sensor = _make_sensor(tmp_path)

    def _fake_run(cmd, **kwargs):
        script = _script_of((cmd,))

        class _R:
            returncode = 0
            stdout = "[]" if "BluetoothLEAdvertisementWatcher" in script else PNP_ARRAY
        return _R()

    monkeypatch.setattr(
        "src.sensors.windows.bluetooth_sensor.shutil.which", lambda _c: "powershell"
    )
    monkeypatch.setattr(
        "src.sensors.windows.bluetooth_sensor.subprocess.run", _fake_run
    )

    reading = sensor._scan()
    # Fell back to PnP and still found the two addressable devices.
    assert reading["device_count"] == 2
    assert reading["new_device_count"] == 2


def test_scan_tracks_new_devices_across_calls(tmp_path, monkeypatch):
    sensor = _make_sensor(tmp_path)

    class _R:
        returncode = 0
        stdout = BLE_ARRAY

    monkeypatch.setattr(
        "src.sensors.windows.bluetooth_sensor.shutil.which", lambda _c: "powershell"
    )
    monkeypatch.setattr(
        "src.sensors.windows.bluetooth_sensor.subprocess.run", lambda *a, **k: _R()
    )

    assert sensor._scan()["new_device_count"] == 2
    assert sensor._scan()["new_device_count"] == 0  # nothing new second time


def test_connect_false_when_powershell_missing(monkeypatch):
    monkeypatch.setattr(
        "src.sensors.windows.bluetooth_sensor.shutil.which", lambda _c: None
    )
    sensor = WindowsBluetoothSensor("bluetooth_sensor", {})
    assert sensor.connect() is False
