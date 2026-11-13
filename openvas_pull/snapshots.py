"""Snapshot IDs follow the receiver's strict ISO 8601 UTC format."""
from datetime import datetime, timezone
import re
import time


def build_snapshot_id(epoch=None):
    return datetime.fromtimestamp(time.time() if epoch is None else epoch, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def valid_snapshot_id(value):
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', str(value)):
        return False
    try:
        datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
        return True
    except ValueError:
        return False
