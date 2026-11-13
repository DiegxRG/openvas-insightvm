#!/bin/bash
# No collector is started. Empty queues make no HTTP requests.
set -euo pipefail
umask 077
PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$PROJECT_DIR"
export PYTHONDONTWRITEBYTECODE=1
mkdir -p cloud_audit_log runtime/openvas
exec >> "$PROJECT_DIR/cloud_audit_log/retry.log" 2>&1
# Same lock as weekly collection/delivery; silently defer if it is busy.
exec /usr/bin/flock -n -E 0 "$PROJECT_DIR/runtime/openvas/weekly_validation.lock" \
    "$PROJECT_DIR/.venv/bin/python" "$PROJECT_DIR/main.py" \
    --env-file "$PROJECT_DIR/.env" --retry-pending
