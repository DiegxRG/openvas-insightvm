#!/bin/bash
# OpenVAS weekly cycle. The only optional argument disables backend delivery.
set -euo pipefail
umask 077
if (( $# > 1 )) || { (( $# == 1 )) && [[ $1 != --no-backend ]]; }; then
    printf 'Uso: %s [--no-backend]\n' "$0" >&2
    exit 2
fi
PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$PROJECT_DIR"
export PYTHONDONTWRITEBYTECODE=1
mkdir -p cloud_audit_log runtime/openvas
exec >> "$PROJECT_DIR/cloud_audit_log/cron.log" 2>&1
mode=delivery
if (( $# )); then
    mode=no-backend
fi
printf '\n[%s] OpenVAS weekly snapshot start mode=%s\n' "$(date -Iseconds)" "$mode"
if /usr/bin/flock -w 300 -E 75 "$PROJECT_DIR/runtime/openvas/weekly_validation.lock" \
    "$PROJECT_DIR/.venv/bin/python" "$PROJECT_DIR/main.py" \
    --env-file "$PROJECT_DIR/.env" --once "$@"; then
    printf '[%s] OpenVAS weekly snapshot complete exit=0\n' "$(date -Iseconds)"
else
    status=$?
    if (( status == 75 )); then
        printf '[%s] OpenVAS weekly snapshot lock timed out after 300s\n' "$(date -Iseconds)"
    fi
    printf '[%s] OpenVAS weekly snapshot failed exit=%s\n' "$(date -Iseconds)" "$status"
    exit "$status"
fi
