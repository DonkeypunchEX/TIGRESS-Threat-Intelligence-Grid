#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

echo '🐯 TIGRESS — Threat Intelligence Grid'
echo '======================================'

cd "$(dirname "$0")/.."

SECURE=false
TRAINING=false
DUMMY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --secure)   SECURE=true ;;
        --train)    TRAINING=true ;;
        --dummy)    DUMMY=true ;;
        --harden)   bash scripts/harden.sh; exit 0 ;;
        *)          echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

mkdir -p data/raw data/alerts data/audit models config/secure

if [ "$SECURE" = true ]; then
    echo '🔒 Verifying secure boot...'
    python -c "
from src.security.secure_boot import SecureBoot
sb = SecureBoot()
if not sb.verify_manifest():
    print('❌ Boot verification failed — system may be compromised')
    exit(1)
print('✅ Boot verification passed')
" || exit 1
fi

termux-wake-lock
echo '🔒 Wake lock active'

umask 077
ulimit -c 0   # Disable core dumps

CMD="python -m src.dashboard.app"
[ "$DUMMY"     = true ] && CMD="$CMD --dummy"
[ "$TRAINING"  = true ] && CMD="$CMD --train"
[ "$SECURE"    = true ] && CMD="$CMD --secure"

nohup $CMD >> data/tigress.log 2>&1 &
PID=$!

echo $PID > data/tigress.pid
chmod 600 data/tigress.pid

echo "✅ TIGRESS running (PID $PID)"
echo "   Mode: $([ "$SECURE" = true ] && echo 'SECURE' || echo 'standard')$([ "$TRAINING" = true ] && echo ' [training]' || echo '')"
echo "🌐 Dashboard: http://127.0.0.1:8080"
echo ""
echo "Logs:  tail -f data/tigress.log"
echo "Audit: tail -f data/audit/audit_$(date +%Y%m%d).log"
echo "Stop:  kill \$(cat data/tigress.pid)"
