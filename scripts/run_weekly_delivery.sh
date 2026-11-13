#!/bin/bash
# Authorized production entry point; BACKEND_ENABLED in .env controls delivery.
set -euo pipefail
umask 077
PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$PROJECT_DIR"
export PYTHONDONTWRITEBYTECODE=1
mkdir -p cloud_audit_log runtime/openvas
exec >> "$PROJECT_DIR/cloud_audit_log/cron.log" 2>&1
printf '\n[%s] OpenVAS weekly snapshot delivery\n' "$(date -Iseconds)"
# Share the lock with the collection-only launcher to prevent overlap.
exec /usr/bin/flock -n -E 75 "$PROJECT_DIR/runtime/openvas/weekly_validation.lock" \
    "$PROJECT_DIR/.venv/bin/python" "$PROJECT_DIR/main.py" \
    --env-file "$PROJECT_DIR/.env" --once
