"""Durable full-snapshot outbox. HTTP payloads are immutable across retries."""
from contextlib import contextmanager
import hashlib
import json
import logging
import os
from pathlib import Path
import sqlite3
import time
from openvas_pull.snapshots import build_snapshot_id, valid_snapshot_id

MAX_DELIVERY_ATTEMPTS = 3
log = logging.getLogger(__name__)


def confirmed_receipt(response, payload):
    if not 200 <= response.get('http_status', 0) < 300:
        return False
    if response.get('idempotent_replay_confirmed') is True:
        return True
    data = response.get('data')
    if response.get('success') is not True or not isinstance(data, dict):
        return False
    expected = len(payload['alarms'])
    return (data.get('snapshot_id') == payload['snapshot_id']
            and all(type(data.get(key)) is int and data[key] == expected
                    for key in ('total_alarmas', 'registros_exitosos'))
            and data.get('errores') in (None, []))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def scope_key(settings):
    return hashlib.sha256(canonical([
        settings.backend_url, settings.backend_local, settings.gvm_host, settings.gvm_port,
        settings.gvm_user, sorted(settings.task_ids), sorted(settings.severities),
    ]).encode()).hexdigest()


def normalized_cves(value):
    values = value.split(',') if isinstance(value, str) else (value or [])
    return sorted({str(v).strip().upper() for v in values if str(v).strip()})


def fingerprint(alarm, finding=None):
    # Observation timestamps and scan/report UUIDs are not content changes.
    semantic = {k: v for k, v in alarm.items() if k != 'fechaalarma'}
    semantic['cves'] = normalized_cves(alarm.get('cves'))
    if semantic.get('cvss_score') is not None:
        semantic['cvss_score'] = float(semantic['cvss_score'])
    occurrences = (finding or {}).get('occurrences', [])
    if occurrences:
        semantic['occurrences'] = sorted({canonical([
            str(o.get('port', '')), str(o.get('severity') or '').lower(),
            float(o['cvss_score']) if o.get('cvss_score') is not None else None,
            normalized_cves(o.get('cves')),
        ]) for o in occurrences})
    return hashlib.sha256(canonical(semantic).encode()).hexdigest()


@contextmanager
def sender_lock(path):
    """OS-owned lock: released on process death, no expiring-lease race."""
    handle = path.open('a+b')
    locked = False
    try:
        handle.seek(0, 2)
        if handle.tell() == 0:
            handle.write(b'0'); handle.flush()
        handle.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RuntimeError('Another sender is active for this delivery scope') from exc
        locked = True
        yield
    finally:
        if locked:
            handle.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


class Outbox:
    def __init__(self, path):
        self.db = sqlite3.connect(path, timeout=10)
        try:
            os.chmod(path, 0o600)
            self.db.row_factory = sqlite3.Row
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL)')
            versions = self.db.execute('SELECT version FROM schema_version').fetchall()
            if versions and (len(versions) != 1 or versions[0][0] not in (1, 2, 3, 4)):
                raise ValueError('Unsupported delivery database schema')
            if versions and versions[0][0] == 1:
                if self.db.execute("SELECT count(*) FROM events WHERE status='pending'").fetchone()[0]:
                    raise ValueError('Legacy per-alarm pending deliveries exist; migration blocked. Preserve database and reconcile before snapshot activation; see docs/DELIVERY.md')
            if versions and versions[0][0] == 2:
                pending = self.db.execute("SELECT snapshot_id FROM snapshot_events WHERE status='pending'").fetchall()
                if any(not valid_snapshot_id(row[0]) for row in pending):
                    raise ValueError('Pending legacy UUID snapshots exist; migration blocked. Preserve their payloads and reconcile IDs before sending; see docs/DELIVERY.md')
            # Legacy v1 tables are preserved for audit; they are never posted as snapshots.
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS snapshot_checkpoints(
                    scope TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
                    started_at REAL NOT NULL, force_next INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS snapshot_events(
                    id INTEGER PRIMARY KEY, scope TEXT NOT NULL, snapshot_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL, payload TEXT NOT NULL, context TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt REAL NOT NULL DEFAULT 0, created_at REAL NOT NULL,
                    acked_at REAL, last_error TEXT, UNIQUE(scope,snapshot_id));
                CREATE INDEX IF NOT EXISTS snapshot_fifo ON snapshot_events(scope,status,id);
                CREATE TABLE IF NOT EXISTS snapshot_clocks(scope TEXT PRIMARY KEY, last_epoch INTEGER NOT NULL);
                INSERT OR IGNORE INTO snapshot_clocks
                    SELECT scope,MAX(CAST(strftime('%s',snapshot_id) AS INTEGER)) FROM snapshot_events
                    WHERE strftime('%s',snapshot_id) IS NOT NULL GROUP BY scope;
            """)
            if not versions or versions[0][0] != 4:
                with self.db:
                    self.db.execute('DELETE FROM schema_version')
                    self.db.execute('INSERT INTO schema_version VALUES(4)')
        except BaseException:
            self.db.close()
            raise

    def enqueue(self, scope, alarms, findings, complete, now, snapshot_started_at, dedup=True):
        counts = dict(new=0, changed=0, unchanged=0)
        if not complete:
            return {**counts, 'incomplete_snapshot': True}
        contexts = {f"{f['asset_id']}_{f['vulnerability_id']}": f for f in (findings or [])}
        seen = {}
        for alarm in alarms:
            identity = str(alarm.get('finding_id') or '')
            if not identity:
                raise ValueError('Missing finding_id in prepared alarm')
            if identity in seen:
                raise ValueError('Duplicate finding_id in snapshot; refusing ambiguous full snapshot')
            seen[identity] = fingerprint(alarm, contexts.get(identity))
            if not isinstance(alarm.get('cves'), list):
                raise ValueError('Snapshot alarm cves must be a list; regenerate prepared payload')
        digest = hashlib.sha256(canonical(sorted(seen.items())).encode()).hexdigest()
        with self.db:
            previous = self.db.execute('SELECT * FROM snapshot_checkpoints WHERE scope=?', (scope,)).fetchone()
            if previous and snapshot_started_at < previous['started_at']:
                return {**counts, 'stale_snapshot': True}
            unchanged = previous and previous['fingerprint'] == digest and not previous['force_next'] and dedup
            if unchanged:
                self.db.execute('UPDATE snapshot_checkpoints SET started_at=? WHERE scope=?', (snapshot_started_at, scope))
                return {**counts, 'unchanged': 1}
            # New observation => new ID. Retries use the exact stored ID and entire payload.
            clock = self.db.execute('SELECT last_epoch FROM snapshot_clocks WHERE scope=?', (scope,)).fetchone()
            epoch = max(int(now), clock[0] + 1 if clock else int(now))
            snapshot_id = build_snapshot_id(epoch)
            self.db.execute('INSERT INTO snapshot_clocks VALUES(?,?) ON CONFLICT(scope) DO UPDATE SET last_epoch=excluded.last_epoch', (scope, epoch))
            payload = {'snapshot_id': snapshot_id, 'alarms': alarms}
            self.db.execute("""INSERT INTO snapshot_events(scope,snapshot_id,fingerprint,payload,context,created_at)
                VALUES(?,?,?,?,?,?)""", (scope, snapshot_id, digest, canonical(payload), canonical(findings or []), now))
            self.db.execute("""INSERT INTO snapshot_checkpoints VALUES(?,?,?,0)
                ON CONFLICT(scope) DO UPDATE SET fingerprint=excluded.fingerprint,
                started_at=excluded.started_at,force_next=0""", (scope, digest, snapshot_started_at))
            return {**counts, 'changed' if previous else 'new': 1, 'snapshot_id': snapshot_id}

    def head(self, scope):
        # A snapshot under review keeps its place until the receiver is reconciled.
        return self.db.execute("""SELECT * FROM snapshot_events
            WHERE scope=? AND status IN ('pending', 'review', 'retry_once') ORDER BY id LIMIT 1""",
            (scope,)).fetchone()

    def acknowledge(self, identity, now):
        with self.db:
            self.db.execute("UPDATE snapshot_events SET status='acked',acked_at=?,last_error=NULL WHERE id=?", (now, identity))

    def begin_attempt(self, event, now, settings):
        # Reserve the attempt before HTTP. Process death cannot reset the budget.
        delay = min(settings.delivery_retry_max_seconds,
                    settings.delivery_retry_seconds * 2 ** min(event['attempts'], 20))
        last = event['status'] == 'retry_once' or event['attempts'] + 1 >= MAX_DELIVERY_ATTEMPTS
        status = 'review' if last else 'pending'
        with self.db:
            self.db.execute("""UPDATE snapshot_events
                SET status=?,attempts=attempts+1,next_attempt=?,last_error=? WHERE id=?""",
                (status, now + delay, 'Delivery interrupted or outcome unknown', event['id']))
        return status, delay

    def record_failure(self, identity, status, message, next_attempt=0):
        with self.db:
            self.db.execute('UPDATE snapshot_events SET status=?,last_error=?,next_attempt=? WHERE id=?',
                            (status, message, next_attempt, identity))

    def prune(self, scope, now, days):
        with self.db:
            self.db.execute("DELETE FROM snapshot_events WHERE scope=? AND status='acked' AND acked_at<?",
                            (scope, now - days * 86400))


def deliver(client, prepared, *, findings=None, complete_snapshot=False, snapshot_started_at=None, retry_only=False):
    settings = client.settings
    path = Path(settings.delivery_state_path).resolve()
    if retry_only and not path.exists():
        return {'enabled': True, 'retry_only': True, 'skipped': True, 'reason': 'no_database',
                'attempted': 0, 'sent_ok': 0, 'snapshots_sent': 0, 'replayed_snapshots': 0,
                'backend_errors': 0, 'conflicts': 0, 'pending_total': 0, 'review_total': 0, 'details': []}
    path.parent.mkdir(parents=True, exist_ok=True)
    scope = scope_key(settings)
    with sender_lock(path.with_name(path.name + '.' + scope + '.lock')):
        store = Outbox(path)
        try:
            now = time.time()
            complete = complete_snapshot and not prepared.get('validation_errors')
            if complete and not isinstance(prepared.get('alarms'), list):
                raise ValueError('Missing/invalid alarms list; refusing an implicit empty snapshot')
            counts = {'retry_only': True} if retry_only else store.enqueue(scope, prepared.get('alarms', []), findings, complete, now,
                                   now if snapshot_started_at is None else snapshot_started_at,
                                   dedup=settings.delivery_dedup_enabled)
            if counts.get('snapshot_id'):
                prepared['snapshot_id'] = counts['snapshot_id']
                prepared['request_payload'] = {'snapshot_id': counts['snapshot_id'], 'alarms': prepared.get('alarms', [])}
            result = {'enabled': True, 'skipped': not complete and not retry_only, 'retry_only': retry_only, 'dedup_enabled': settings.delivery_dedup_enabled,
                      'total_filtered_findings': prepared.get('total_filtered_findings', 0),
                      'prepared_alarms': len(prepared.get('alarms', [])),
                      'validation_errors': prepared.get('validation_errors', 0),
                      'sent_ok': 0, 'snapshots_sent': 0, 'replayed_snapshots': 0, 'conflicts': 0,
                      'backend_errors': 0 if complete or retry_only else 1,
                      'queued': counts, 'attempted': 0, 'new_reviews': 0,
                      'details': list(prepared.get('skipped_findings', []))}
            while True:
                event = store.head(scope)
                now = time.time()
                if event is None or event['status'] == 'review':
                    break
                if event['status'] == 'pending' and event['attempts'] >= MAX_DELIVERY_ATTEMPTS:
                    reason = 'Automatic delivery budget already exhausted'
                    store.record_failure(event['id'], 'review', reason)
                    log.error('snapshot_id=%s requires review: %s', event['snapshot_id'], reason)
                    result['new_reviews'] += 1
                    break
                if event['next_attempt'] > now:
                    break
                payload = json.loads(event['payload'])
                attempt_status, delay = store.begin_attempt(event, now, settings)
                response = client._post_snapshot(payload)
                result['attempted'] += 1
                result['details'].append(response)
                if confirmed_receipt(response, payload):
                    store.acknowledge(event['id'], time.time())
                    result['sent_ok'] += len(payload['alarms'])
                    result['snapshots_sent'] += 1
                    result['replayed_snapshots'] += int(response.get('idempotent_replay_confirmed') is True)
                else:
                    if 'Ya existe un registro activo' in str(response.get('message', '')):
                        result['conflicts'] += 1
                    else:
                        result['backend_errors'] += 1
                    receipt = response.get('data')
                    accepted = receipt.get('registros_exitosos') if isinstance(receipt, dict) else None
                    reported_acceptance = type(accepted) is int and accepted > 0
                    retryable = response.get('retryable') is True and not reported_acceptance
                    status = attempt_status if retryable else 'review'
                    status_code = response.get('http_status', 0)
                    if reported_acceptance or 200 <= status_code < 300:
                        reason = f'HTTP {status_code}: invalid or incomplete receipt'
                    elif status_code:
                        reason = f'HTTP {status_code}: unconfirmed delivery'
                    else:
                        reason = 'Backend connection failed'
                    next_attempt = time.time() + delay if status == 'pending' else 0
                    store.record_failure(event['id'], status, reason, next_attempt)
                    if status == 'review':
                        log.error('snapshot_id=%s requires review: %s', event['snapshot_id'], reason)
                        result['new_reviews'] += 1
                    break
            statuses = dict(store.db.execute("""SELECT status,count(*) FROM snapshot_events
                WHERE scope=? AND status IN ('pending', 'review', 'retry_once') GROUP BY status""", (scope,)))
            result['pending_total'] = statuses.get('pending', 0) + statuses.get('retry_once', 0)
            result['review_total'] = statuses.get('review', 0)
            store.prune(scope, time.time(), settings.delivery_ack_retention_days)
            return result
        finally:
            store.db.close()
