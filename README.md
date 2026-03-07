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

## Models
Trained models are saved to `models/`. Delete them to retrain. The engine falls back to rule-based detection until training is complete.

## Audit Logs
Logs are written to `data/audit/audit_YYYYMMDD.log`. Each entry is ECDSA-signed and hash-chained. Verify integrity:
```python
from src.security.audit_log import AuditLog
print(AuditLog().verify_integrity())
```

## License
MIT
```

---

**`requirements.txt`**
```
# Core
numpy>=1.24
scikit-learn>=1.3
pandas>=2.0
joblib>=1.3

# Security
cryptography>=41.0
bcrypt>=4.0
PyJWT>=2.8

# API / Dashboard
fastapi>=0.104
uvicorn[standard]>=0.24
httpx>=0.25
python-multipart>=0.0.6

# System
psutil>=5.9
pyyaml>=6.0
```

---

**`.gitignore`**
```
__pycache__/
*.py[cod]
*.so
*.egg-info/
dist/
build/
venv/
env/

# Secrets & generated files
.env
config/secure/
config/manifest.key
config/manifest.json
certs/*.key
certs/*.crt

# Data
data/raw/
data/alerts/
data/audit/
data/*.pid
data/*.log
models/*.pkl
data/known_bssids.txt

# OS
.DS_Store
Thumbs.db
```

---

## Step 2 — Empty placeholder files (keeps folders tracked by git)

Create these empty files exactly as listed:
```
data/raw/.gitkeep
data/alerts/.gitkeep
data/audit/.gitkeep
models/.gitkeep
certs/.gitkeep
