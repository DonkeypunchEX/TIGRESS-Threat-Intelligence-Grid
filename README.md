# TIGRESS – Threat Intelligence Grid for Android

Security monitoring framework for Android/Termux: WiFi anomaly detection, physical tamper detection, and ML-based threat analysis.

## Features
- WiFi scanning with new-BSSID and SSID-rule alerting
- Accelerometer-based tamper detection
- Isolation Forest anomaly detection (auto-trains on first run)
- Encrypted configuration (hardware-backed when available)
- Tamper-proof audit logging (hash chain + ECDSA signatures)
- Runtime file and process integrity monitoring
- Mutual TLS for dashboard communication
- Termux push notifications

## Limitations (Android 13+)
- `termux-wifi-scaninfo` returns cached data — scans may be stale
- Accelerometer sensor name is auto-detected per device
- ML models require a training pass before anomaly detection activates
- For background operation: use `termux-wake-lock` and keep Termux in the foreground

## Installation
```bash
pkg install python termux-api
pip install -r requirements.txt
bash scripts/harden.sh
```

## Usage
```bash
# Training mode — collect baseline data
bash scripts/tigress_launcher.sh --train

# Normal operation
bash scripts/tigress_launcher.sh

# Secure mode (verifies boot manifest before starting)
bash scripts/tigress_launcher.sh --secure

# Demo mode (no real sensors required)
bash scripts/tigress_launcher.sh --dummy
```

The dashboard listens on the host/port from the `server` section of
`config/config.yaml` (default `127.0.0.1:8080`).

## Configuration
`config/config.yaml` controls sensors, detection thresholds, and alerting.
Per-sensor `buffer_limit` (default 1000) caps how many recent readings each
sensor keeps in memory. Detection rules live in `config/rules.yaml`.

## Models
Trained models are saved to `models/`. Delete them to retrain. The engine falls
back to rule-based detection until training is complete.

## Audit Logs
Logs are written to `data/audit/audit_YYYYMMDD.log`. Each entry is ECDSA-signed
and hash-chained. Verify integrity:
```python
from src.security.audit_log import AuditLog
print(AuditLog().verify_integrity())
```

## Development & Testing
```bash
pip install -r requirements-dev.txt
pytest
```
The test suite is hermetic — it writes only to pytest temp directories and does
not require real sensors or Termux.

## License
MIT
