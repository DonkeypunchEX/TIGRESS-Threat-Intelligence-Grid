#!/usr/bin/env python3
"""One-command end-to-end demo of the TIGRESS detection pipeline.

Runs entirely on the local machine — no Android, Termux, or network services
required. It:

  1. starts a local HTTP webhook receiver,
  2. builds a real DetectionEngine wired to that webhook alert channel,
  3. feeds it threat-shaped WiFi and Bluetooth scans,
  4. shows detections firing, alerts delivered over HTTP, and the
     bearer-authenticated /detections API returning the stored detections.

Usage:
    python scripts/demo_end_to_end.py
"""

import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Make the repository importable when run as `python scripts/demo_end_to_end.py`.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import yaml  # noqa: E402

from src.core.detection_engine import DetectionEngine  # noqa: E402

DELIVERED = []  # alerts the webhook received


class _WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        DELIVERED.append(json.loads(self.rfile.read(length)))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):  # silence default request logging
        pass


def _banner(text):
    print(f"\n\033[1m=== {text} ===\033[0m")


def _write_config(tmp, webhook_url):
    models = tmp / "models"
    (tmp / "rules.yaml").write_text(yaml.safe_dump({
        "wifi_rules": [{
            "id": "ssid_spoof_suspect", "enabled": True,
            "description": "SSID not in corporate whitelist",
            "severity": 3, "confidence": 0.8,
            "conditions": [{"field": "SSID", "op": "not_contains", "value": "CorpNet"}],
        }],
        "bluetooth_rules": [
            {"id": "ble_close_proximity", "enabled": True,
             "description": "Bluetooth device in very close proximity (strong RSSI)",
             "severity": 3, "confidence": 0.75,
             "conditions": [{"field": "rssi", "op": "gt", "value": "-50"}]},
            {"id": "ble_tracker_suspect", "enabled": True,
             "description": "Bluetooth device name matches a tracker pattern",
             "severity": 4, "confidence": 0.8,
             "conditions": [{"field": "name", "op": "contains", "value": "AirTag"}]},
        ],
    }))
    cfg = {
        "sensors": {"wifi": {"alert_threshold": 3}, "bluetooth": {"alert_threshold": 3}},
        "detection": {
            "confidence_threshold": 0.6,
            "rules_file": str(tmp / "rules.yaml"),
            "ml_models": {
                "wifi": str(models / "wifi.pkl"),
                "phone": str(models / "phone.pkl"),
                "bluetooth": str(models / "bluetooth.pkl"),
            },
            "training_samples": 300,
        },
        "alerting": {
            "forensic_log": str(tmp / "forensic.jsonl"),
            "channels": {
                "termux": {"enabled": False},
                "webhook": {"enabled": True, "url": webhook_url, "min_severity": 1},
            },
        },
    }
    path = tmp / "config.yaml"
    path.write_text(yaml.safe_dump(cfg))
    return str(path)


def _show(label, detections):
    print(f"  {label}: {len(detections)} detection(s)")
    for d in detections:
        print(f"    • [sev {d.severity}] {d.description}")


def main():
    """Run the full local demo and print each stage's result."""
    import shutil
    from pathlib import Path

    tmp = Path(tempfile.mkdtemp(prefix="tigress-demo-"))
    server = None
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _WebhookHandler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        webhook_url = f"http://127.0.0.1:{port}/alert"

        print("TIGRESS end-to-end demo (no Android required)")
        print(f"  workdir:  {tmp}")
        print(f"  webhook:  {webhook_url}")

        config_path = _write_config(tmp, webhook_url)
        engine = DetectionEngine(config_path)

        _banner("1. Feeding threat-shaped sensor readings")

        _show("Rogue WiFi SSID", engine.analyze_wifi([{
            "networks": [{"SSID": "Free_Airport_WiFi", "BSSID": "de:ad:be:ef:00:01"}],
            "ap_count": 1, "new_ap_count": 0, "new_bssids": [],
        }]))
        _show("WiFi new-AP surge", engine.analyze_wifi([{
            "networks": [{"SSID": "CorpNet", "BSSID": "aa:bb:cc:dd:ee:01"}],
            "ap_count": 8, "new_ap_count": 7,
            "new_bssids": [f"aa:bb:cc:dd:ee:{i:02x}" for i in range(7)],
        }]))
        _show("BLE tracker nearby", engine.analyze_bluetooth([{
            "devices": [{"address": "11:22:33:44:55:66", "name": "John's AirTag", "rssi": -38}],
            "device_count": 1, "new_device_count": 0, "new_devices": [],
        }]))
        _show("BLE new-device surge", engine.analyze_bluetooth([{
            "devices": [{"address": "77:88:99:aa:bb:cc", "name": "Unknown", "rssi": -75}],
            "device_count": 6, "new_device_count": 6,
            "new_devices": [f"77:88:99:aa:bb:{i:02x}" for i in range(6)],
        }]))

        _banner("2. Alerts delivered to the webhook")
        print(f"  {len(DELIVERED)} alert(s) received over HTTP:")
        for a in DELIVERED:
            print(f"    → sev {a['severity']}: {a['content']}  [{a['title']}]")

        _banner("3. Detection history + summary (backs the /detections API)")
        print(f"  stored detections: {len(engine.history)}")
        print(f"  summary: {json.dumps(engine.history.summary())}")
        forensic = tmp / "forensic.jsonl"
        if forensic.exists():
            lines = forensic.read_text().splitlines()
            print(f"  forensic log: {len(lines)} fsynced JSONL record(s) at {forensic.name}")

        _banner("4. Authenticated /detections API")
        _demo_api(engine)

        print("\n\033[1mDone.\033[0m The full pipeline ran end-to-end with no Android or "
              "external services.")
    finally:
        if server is not None:
            server.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


def _demo_api(engine):
    try:
        from types import SimpleNamespace

        from fastapi.testclient import TestClient

        from src.dashboard import app as appmod
    except Exception as e:  # fastapi/httpx not installed
        print(f"  (skipped — dashboard deps unavailable: {e})")
        return

    appmod._manager = SimpleNamespace(
        detection_engine=engine, list_sensors=lambda: [], is_running=True,
    )
    appmod._api_token = "demo-token"
    client = TestClient(appmod.app)

    no_auth = client.get("/detections")
    print(f"  GET /detections           (no token)  -> {no_auth.status_code} (expected 401)")
    ok = client.get("/detections", headers={"Authorization": "Bearer demo-token"})
    print(f"  GET /detections           (with token)-> {ok.status_code}, {len(ok.json())} detections")
    summary = client.get("/detections/summary", headers={"Authorization": "Bearer demo-token"})
    print(f"  GET /detections/summary   (with token)-> {summary.status_code}, {json.dumps(summary.json())}")


if __name__ == "__main__":
    main()
