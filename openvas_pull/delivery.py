"""Durable, single-host delivery outbox. Does not alter backend alarm payloads."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def scope_key(settings):
    return hashlib.sha256(canonical([
        settings.backend_url, settings.backend_local, settings.gvm_host, settings.gvm_port,
        settings.gvm_user, sorted(settings.task_ids), sorted(settings.severities),
    ]).encode()).hexdigest()


def fingerprint(alarm, finding=None):
    # Observation time/report UUID alone is not a new vulnerability or a change.
    semantic = {k: v for k, v in alarm.items() if k != 'fechaalarma'}
    semantic['cves'] = sorted({v.strip().upper() for v in str(alarm.get('cves', '')).split(',') if v.strip()})
    if semantic.get('cvss_score') is not None:
        semantic['cvss_score'] = float(semantic['cvss_score'])
    occurrences = (finding or {}).get('occurrences', [])
    if occurrences:
        # New ports / changed per-port severity must not disappear in grouping.
        semantic['occurrences'] = sorted({canonical([
            str(o.get('port', '')), o.get('severity'), o.get('cvss_score'),
            sorted(set(o.get('cves', []))),
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
            self._initialize(path)
        except BaseException:
            self.db.close()
            raise

    def _initialize(self, path):
        os.chmod(path, 0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
            INSERT INTO schema_version SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);
            CREATE TABLE IF NOT EXISTS findings(
                scope TEXT NOT NULL, finding_id TEXT NOT NULL, current_hash TEXT NOT NULL,
                generation INTEGER NOT NULL, active INTEGER NOT NULL, observed_at REAL NOT NULL,
                PRIMARY KEY(scope, finding_id));
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY, scope TEXT NOT NULL, finding_id TEXT NOT NULL,
                generation INTEGER NOT NULL, fingerprint TEXT NOT NULL, payload TEXT NOT NULL,
                context TEXT NOT NULL,
                reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0,
                created_at REAL NOT NULL, acked_at REAL, last_error TEXT);
            CREATE INDEX IF NOT EXISTS events_due ON events(scope,status,next_attempt,id);
            CREATE INDEX IF NOT EXISTS events_finding ON events(scope,finding_id,status,id);
            CREATE TABLE IF NOT EXISTS snapshots(scope TEXT PRIMARY KEY, started_at REAL NOT NULL);
        ''')
        if self.db.execute('SELECT version FROM schema_version').fetchone()[0] != 1:
            raise ValueError('Unsupported delivery database schema')

    def enqueue(self, scope, alarms, findings, complete, now, snapshot_started_at):
        contexts = {f"{f['asset_id']}_{f['vulnerability_id']}": f for f in (findings or [])}
        counts = dict(new=0, changed=0, reappeared=0, unchanged=0)
        if not alarms and not complete:
            return counts  # Queue draining is not a new observation of the source.
        seen = {}
        with self.db:
            previous_snapshot = self.db.execute('SELECT started_at FROM snapshots WHERE scope=?', (scope,)).fetchone()
            if previous_snapshot and snapshot_started_at < previous_snapshot[0]:
                return {**counts, 'stale_snapshot': True}
            if complete:
                self.db.execute('INSERT INTO snapshots VALUES(?,?) ON CONFLICT(scope) DO UPDATE SET started_at=excluded.started_at',
                                (scope, snapshot_started_at))
            self.db.execute('CREATE TEMP TABLE IF NOT EXISTS observed(id TEXT PRIMARY KEY)')
            self.db.execute('DELETE FROM observed')
            for alarm in alarms:
                identity = str(alarm.get('finding_id') or '')
                if not identity:
                    raise ValueError('Missing finding_id in prepared alarm')
                digest = fingerprint(alarm, contexts.get(identity))
                if identity in seen:
                    if seen[identity] != digest:
                        raise ValueError('Conflicting duplicate finding_id in the same snapshot')
                    continue
                seen[identity] = digest
                self.db.execute('INSERT INTO observed VALUES(?)', (identity,))
                previous = self.db.execute('SELECT * FROM findings WHERE scope=? AND finding_id=?', (scope, identity)).fetchone()
                if previous and snapshot_started_at < previous['observed_at']:
                    counts['stale_findings'] = counts.get('stale_findings', 0) + 1
                    continue
                if previous is None:
                    reason, generation = 'new', 1
                elif not previous['active']:
                    reason, generation = 'reappeared', previous['generation'] + 1
                elif previous['current_hash'] != digest:
                    reason, generation = 'changed', previous['generation']
                else:
                    counts['unchanged'] += 1
                    self.db.execute('UPDATE findings SET observed_at=? WHERE scope=? AND finding_id=?',
                                    (snapshot_started_at, scope, identity))
                    continue
                self.db.execute('''INSERT INTO findings VALUES(?,?,?,?,1,?)
                    ON CONFLICT(scope,finding_id) DO UPDATE SET current_hash=excluded.current_hash,
                    generation=excluded.generation,active=1,observed_at=excluded.observed_at''',
                                (scope, identity, digest, generation, snapshot_started_at))
                self.db.execute('''INSERT INTO events(scope,finding_id,generation,fingerprint,payload,context,reason,created_at)
                    VALUES(?,?,?,?,?,?,?,?)''', (scope, identity, generation, digest, canonical(alarm),
                                               canonical(contexts.get(identity, {})), reason, now))
                counts[reason] += 1
            if complete:
                self.db.execute('''UPDATE findings SET active=0,observed_at=? WHERE scope=? AND active=1
                    AND observed_at<=? AND finding_id NOT IN (SELECT id FROM observed)''',
                                (snapshot_started_at, scope, snapshot_started_at))
        return counts

    def due(self, scope, now, size):
        # Preserve per-finding order so an old retry cannot overwrite a newer change.
        return self.db.execute('''SELECT e.id,e.payload,e.attempts FROM events e WHERE e.scope=? AND e.status='pending'
            AND e.next_attempt<=? AND NOT EXISTS (SELECT 1 FROM events older WHERE
                older.scope=e.scope AND older.finding_id=e.finding_id AND older.status='pending' AND older.id<e.id)
            ORDER BY e.id LIMIT ?''', (scope, now, size)).fetchall()

    def acknowledge(self, identity, now):
        with self.db:
            self.db.execute("UPDATE events SET status='acked',acked_at=?,last_error=NULL WHERE id=?", (now, identity))

    def defer(self, event, now, settings, message):
        delay = min(settings.delivery_retry_max_seconds,
                    settings.delivery_retry_seconds * 2 ** min(event['attempts'], 20))
        with self.db:
            self.db.execute('UPDATE events SET attempts=attempts+1,next_attempt=?,last_error=? WHERE id=?',
                            (now + delay, str(message)[:1000], event['id']))

    def prune(self, scope, now, days):
        with self.db:
            self.db.execute("DELETE FROM events WHERE scope=? AND status='acked' AND acked_at<?",
                            (scope, now - days * 86400))


def deliver(client, prepared, *, findings=None, complete_snapshot=False, snapshot_started_at=None):
    settings = client.settings
    path = Path(settings.delivery_state_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    scope = scope_key(settings)
    with sender_lock(path.with_name(path.name + '.' + scope + '.lock')):
        store = Outbox(path)
        try:
            now = time.time()
            counts = store.enqueue(scope, prepared.get('alarms', []), findings,
                                   complete_snapshot and not prepared.get('validation_errors'), now,
                                   now if snapshot_started_at is None else snapshot_started_at)
            result = {'enabled': True, 'skipped': False, 'dedup_enabled': True,
                      'total_filtered_findings': prepared.get('total_filtered_findings', 0),
                      'prepared_alarms': len(prepared.get('alarms', [])),
                      'validation_errors': prepared.get('validation_errors', 0),
                      'sent_ok': 0, 'conflicts': 0, 'backend_errors': 0,
                      'queued': counts, 'attempted': 0, 'details': list(prepared.get('skipped_findings', []))}
            while True:
                batch = store.due(scope, now, settings.delivery_batch_size)
                if not batch:
                    break
                for event in batch:
                    alarm = json.loads(event['payload'])
                    response = client._post_alarm(alarm)
                    result['attempted'] += 1
                    result['details'].append(response)
                    status = response.get('http_status', 0)
                    if response.get('success') is True and 200 <= status < 300:
                        store.acknowledge(event['id'], time.time())
                        result['sent_ok'] += 1
                    else:
                        if 'Ya existe un registro activo' in str(response.get('message', '')):
                            result['conflicts'] += 1
                        else:
                            result['backend_errors'] += 1
                        # A conflict is not proof that this version was stored.
                        store.defer(event, time.time(), settings, response.get('message', 'Unconfirmed delivery'))
            result['pending_total'] = store.db.execute("SELECT count(*) FROM events WHERE scope=? AND status='pending'", (scope,)).fetchone()[0]
            store.prune(scope, time.time(), settings.delivery_ack_retention_days)
            return result
        finally:
            store.db.close()
