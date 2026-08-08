# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email the maintainer privately (see the repository profile / contact in
`pyproject.toml`) with:

- A clear description of the issue
- Steps to reproduce
- Affected version / commit
- Any proof-of-concept (non-destructive preferred)

You should receive an acknowledgement within 7 days. We aim to ship a fix or
mitigation within 30 days for high-severity issues, then disclose coordinatedly.

## Threat model (summary)

TIGRESS is a **personal / field counter-surveillance** tool, primarily for
Android/Termux. Design assumptions:

- The phone may operate in a hostile RF environment
- Network egress from the phone should be minimized (offline enrichment)
- Write/ingest APIs must never fall open without authentication
- Forensic and audit logs are evidence artifacts and must be tamper-evident
- The host itself may be compromised → `--secure` enables runtime integrity,
  self-validation gates, and optional mTLS

### Known residual risks

- Audit signing keys are stored on disk without encryption (`signing_key.der`)
- Termux WiFi scans on Android 13+ may return cached data
- Default dashboard binds to `127.0.0.1`; if rebound to `0.0.0.0`, always set
  `TIGRESS_API_TOKEN` or run with `--secure` (mTLS)

## Hardening checklist for operators

1. Set `TIGRESS_API_TOKEN` (or `server.api_token`) before exposing any API
2. Prefer `bash scripts/tigress_launcher.sh --secure` in the field
3. Curate `data/trusted_entities.txt` by hand (never auto-seed from `known_*`)
4. Restrict webhook `allowed_hosts` if using the webhook channel
5. Run `python scripts/selftest.py --record-dir data/validation` after upgrades
6. Keep `termux-wake-lock` and the app in the foreground for reliable sensors
