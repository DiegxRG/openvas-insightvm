#!/bin/bash
# Collection-only entry point. Never enable backend delivery in this wrapper.
set -euo pipefail
umask 077
PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$PROJECT_DIR"
export PYTHONDONTWRITEBYTECODE=1
mkdir -p cloud_audit_log runtime/openvas
exec >> "$PROJECT_DIR/cloud_audit_log/cron.log" 2>&1
printf '\n[%s] OpenVAS weekly collection; backend forced off\n' "$(date -Iseconds)"
exec /usr/bin/flock -n -E 75 "$PROJECT_DIR/runtime/openvas/weekly_validation.lock" \
    "$PROJECT_DIR/.venv/bin/python" "$PROJECT_DIR/main.py" \
    --env-file "$PROJECT_DIR/.env" --once --no-backend
