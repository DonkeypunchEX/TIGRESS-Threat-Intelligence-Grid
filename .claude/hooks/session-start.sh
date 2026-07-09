#!/bin/bash
# TIGRESS SessionStart hook: install dependencies so tests run in
# Claude Code on the web. Synchronous and idempotent.
set -euo pipefail

# Only run in the remote (web) environment.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-.}"

# Runtime + dev dependencies (pytest, ML, crypto, dashboard).
python3 -m pip install --quiet -r requirements-dev.txt

# Make `from src...` imports resolve for ad-hoc scripts this session.
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  echo 'export PYTHONPATH="."' >> "$CLAUDE_ENV_FILE"
fi

echo "TIGRESS session-start: dependencies ready."
