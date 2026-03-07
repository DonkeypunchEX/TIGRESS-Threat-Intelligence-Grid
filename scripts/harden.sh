#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

echo '🔒 TIGRESS Hardening'
echo '===================='

HAS_ROOT=false
[ "$EUID" -eq 0 ] && HAS_ROOT=true && echo '⚠️  Running as root' || echo 'ℹ️  No root — limited hardening'

# 1. File permissions
echo '📁 Setting file permissions...'
find config -type f -exec chmod 600 {} \;
find config -type d -exec chmod 700 {} \;
find data   -type f -exec chmod 600 {} \; 2>/dev/null || true
find data   -type d -exec chmod 700 {} \; 2>/dev/null || true
find models -type f -exec chmod 600 {} \; 2>/dev/null || true

# 2. Network hardening (root only)
if [ "$HAS_ROOT" = true ]; then
    echo '🌐 Hardening network stack...'
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
    echo 1 > /proc/sys/net/ipv4/tcp_syncookies
    echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
    echo 1 > /proc/sys/kernel/yama/ptrace_scope
    echo 2 > /proc/sys/kernel/randomize_va_space
fi

# 3. Generate TLS certificates
echo '🔐 Generating certificates...'
python -c "
from src.security.secure_communication import SecureChannel
SecureChannel()
print('✅ Certificates ready')
"

# 4. Initialize encrypted config store
echo '⚙️  Initialising secure config...'
python -c "
from src.security.secure_config import SecureConfig
SecureConfig()
print('✅ Secure config initialised')
"

# 5. Create boot manifest
echo '📝 Creating boot manifest...'
python -c "
from src.security.secure_boot import SecureBoot
SecureBoot().create_manifest()
print('✅ Boot manifest created')
"

# 6. Audit log directory
echo '📋 Securing audit directory...'
mkdir -p data/audit
chmod 700 data/audit

echo ''
echo '✅ Hardening complete'
echo ''
echo 'Next steps:'
echo '  Verify boot: python -c "from src.security.secure_boot import SecureBoot; print(SecureBoot().verify_manifest())"'
echo '  Start:       bash scripts/tigress_launcher.sh --secure'
echo "  Audit:       tail -f data/audit/audit_$(date +%Y%m%d).log"
```

---

## Step 5 — `src/` package init files

Create these as **empty files** (just the filename, no content):
```
src/__init__.py
src/sensors/__init__.py
src/core/__init__.py
src/dashboard/__init__.py
src/security/__init__.py
src/utils/__init__.py
