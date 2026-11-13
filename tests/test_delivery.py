from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading

import pytest

from openvas_pull.backend_client import BackendAlarmClient
from openvas_pull.config import Settings
from openvas_pull.delivery import scope_key, sender_lock


@pytest.fixture
def cfg(tmp_path):
    return Settings(gvm_host='offline', gvm_port=1, gvm_user='dummy', gvm_password='dummy',
                    backend_enabled=True, delivery_state_path=str(tmp_path / 'state.sqlite3'),
                    delivery_batch_size=2, delivery_retry_seconds=1, delivery_retry_max_seconds=4)


@pytest.fixture
def clock(monkeypatch):
    now = [10000.0]
    monkeypatch.setattr('openvas_pull.delivery.time.time', lambda: now[0])
    return now


def prepared(n=1):
    alarm = json.loads((Path(__file__).parent / 'fixtures/insight_reference_alarm.json').read_text())
    alarm['source'] = 'openvas'
    alarm['cves'] = ['CVE-2026-1234']
    alarms = [{**alarm, 'finding_id': f'asset_{i}', 'asset_id': f'asset{i}'} for i in range(n)]
    return {'enabled': True, 'alarms': alarms, 'prepared_alarms_count': n,
            'total_filtered_findings': n, 'validation_errors': 0}


def client(cfg, calls, reply=None):
    result = BackendAlarmClient(cfg)
    class Response:
        status_code = 200
        def json(self): return {'success': True}
    def post(url, **kwargs):
        calls.append(kwargs['json'])
        if reply:
            return reply(kwargs['json'])
        return Response()
    result.session.post = post
    return result


def test_restart_suppresses_all_identical_alarms_without_altering_wire(cfg):
    p = prepared(7); calls = []
    first = client(cfg, calls).send_prepared_alarms(p, complete_snapshot=True)
    second = client(cfg, calls).send_prepared_alarms(p, complete_snapshot=True)
    assert first['sent_ok'] == 7 and second['attempted'] == 0
    assert second['queued']['unchanged'] == 1
    assert len(calls) == 1 and calls[0]['alarms'] == p['alarms']
    assert set(calls[0]) == {'snapshot_id', 'alarms'}


@pytest.mark.parametrize('field,value', [('severity', 'High'), ('cvss_score', 9.9),
    ('cves', ['CVE-2026-10001']), ('vulnerability_title', 'Changed title'), ('servidor', 'new-host')])
def test_new_or_changed_values_are_delivered(cfg, field, value):
    calls = []; p = prepared()
    client(cfg, calls).send_prepared_alarms(p)
    p['alarms'][0][field] = value
    changed = client(cfg, calls).send_prepared_alarms(p)
    assert changed['queued']['changed'] == 1 and changed['sent_ok'] == 1
    p = prepared(2)
    new = client(cfg, calls).send_prepared_alarms(p)
    assert new['queued']['changed'] == 1 and new['sent_ok'] == 2


def test_date_cve_order_and_report_ids_do_not_cause_false_changes(cfg):
    p = prepared(); calls = []
    p['alarms'][0]['cves'] = ['CVE-2026-10001', 'CVE-2026-10002']
    findings = [{'asset_id': 'asset', 'vulnerability_id': '0', 'occurrences': [
        {'report_id': 'a', 'port': '443/tcp', 'severity': 'critical', 'cvss_score': 9.8, 'cves': []}]}]
    client(cfg, calls).send_prepared_alarms(p, findings=findings)
    p['alarms'][0]['fechaalarma'] = '2026-11-13 12:00:00'
    p['alarms'][0]['cves'] = ['CVE-2026-10002', 'CVE-2026-10001']
    findings[0]['occurrences'][0]['report_id'] = 'b'
    assert client(cfg, calls).send_prepared_alarms(p, findings=findings)['attempted'] == 0
    findings[0]['occurrences'].append({'port': '80/tcp', 'severity': 'critical', 'cvss_score': 9.8, 'cves': []})
    assert client(cfg, calls).send_prepared_alarms(p, findings=findings)['sent_ok'] == 1


def test_failure_retries_after_restart_even_when_source_is_empty(cfg, clock):
    calls = []
    def fail(_): raise TimeoutError('simulated timeout')
    result = client(cfg, calls, fail).send_prepared_alarms(prepared())
    assert result['pending_total'] == 1 and result['sent_ok'] == 0
    assert client(cfg, calls).send_prepared_alarms(prepared())['attempted'] == 0
    clock[0] += 2
    retried = client(cfg, calls).send_prepared_alarms(prepared(0), complete_snapshot=False)
    assert retried['sent_ok'] == 1 and retried['pending_total'] == 0


def test_conflict_does_not_ack_a_change_and_preserves_fifo(cfg, clock):
    calls = []; p = prepared()
    class Conflict:
        status_code = 409
        def json(self): return {'success': False, 'message': 'Ya existe un registro activo'}
    first = client(cfg, calls, lambda _: Conflict()).send_prepared_alarms(p)
    assert first['conflicts'] == 1 and first['pending_total'] == 1
    p['alarms'][0]['cvss_score'] = 10.0
    queued = client(cfg, calls).send_prepared_alarms(p)
    assert queued['queued']['changed'] == 1 and queued['pending_total'] == 2
    assert queued['attempted'] == 0  # Never overwrite a newer change with an older retry.
    clock[0] += 2
    done = client(cfg, calls).send_prepared_alarms(prepared(0), complete_snapshot=False)
    assert done['sent_ok'] == 2 and done['pending_total'] == 0
    assert [a['alarms'][0]['cvss_score'] for a in calls[-2:]] == [9.8, 10.0]


def test_http_error_with_success_true_is_not_acknowledged(cfg):
    class Error:
        status_code = 500
        def json(self): return {'success': True}
    r = client(cfg, [], lambda _: Error()).send_prepared_alarms(prepared())
    assert r['sent_ok'] == 0 and r['pending_total'] == 1


def test_reappearance_only_after_complete_snapshot_and_no_automatic_closure_post(cfg):
    calls = []; c = client(cfg, calls)
    c.send_prepared_alarms(prepared(), complete_snapshot=True)
    c.send_prepared_alarms(prepared(0), complete_snapshot=False)
    assert c.send_prepared_alarms(prepared(), complete_snapshot=True)['attempted'] == 0
    c.send_prepared_alarms(prepared(0), complete_snapshot=True)
    r = c.send_prepared_alarms(prepared(), complete_snapshot=True)
    assert r['queued']['changed'] == 1 and r['sent_ok'] == 1
    assert len(calls) == 3 and calls[1]['alarms'] == []


def test_stale_snapshot_cannot_roll_back_current_state(cfg):
    calls = []; c = client(cfg, calls); p = prepared()
    c.send_prepared_alarms(p, complete_snapshot=True, snapshot_started_at=20)
    p['alarms'][0]['cvss_score'] = 7.0
    r = c.send_prepared_alarms(p, complete_snapshot=True, snapshot_started_at=10)
    assert r['queued']['stale_snapshot'] is True and r['attempted'] == 0
    assert len(calls) == 1


def test_a_b_a_changes_are_all_durable_before_delivery(cfg, clock):
    calls = []; p = prepared()
    def fail(_): raise TimeoutError('offline')
    c = client(cfg, calls, fail)
    c.send_prepared_alarms(p)
    p['alarms'][0]['cvss_score'] = 10.0; c.send_prepared_alarms(p)
    p['alarms'][0]['cvss_score'] = 9.8; c.send_prepared_alarms(p)
    clock[0] += 2
    r = client(cfg, calls).send_prepared_alarms(prepared(0), complete_snapshot=False)
    assert r['sent_ok'] == 3
    assert [a['alarms'][0]['cvss_score'] for a in calls[-3:]] == [9.8, 10.0, 9.8]


def test_dry_run_does_not_create_state(cfg):
    r = client(replace(cfg, backend_enabled=False), []).send_prepared_alarms(prepared(), complete_snapshot=True)
    assert r['skipped'] is True and not Path(cfg.delivery_state_path).exists()


def test_scope_isolation_and_history_pruning_do_not_lose_identity(cfg, clock):
    calls = []; client(cfg, calls).send_prepared_alarms(prepared())
    client(replace(cfg, backend_local='other'), calls).send_prepared_alarms(prepared())
    assert len(calls) == 2
    clock[0] += 100 * 86400
    assert client(cfg, calls).send_prepared_alarms(prepared())['attempted'] == 0
    assert client(cfg, calls).send_prepared_alarms(prepared())['attempted'] == 0


def test_enqueue_is_atomic_and_invalid_snapshot_never_sends(cfg):
    p = prepared(2); p['alarms'][1]['finding_id'] = ''
    calls = []
    r = client(cfg, calls).send_prepared_alarms(p)
    assert r['backend_errors'] == 1 and not calls
    with sqlite3.connect(cfg.delivery_state_path) as db:
        assert db.execute('SELECT count(*) FROM snapshot_events').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM snapshot_checkpoints').fetchone()[0] == 0


def test_corrupt_state_fails_closed(cfg):
    Path(cfg.delivery_state_path).write_bytes(b'not a database')
    calls = []
    assert client(cfg, calls).send_prepared_alarms(prepared())['backend_errors'] == 1
    assert calls == []


def test_concurrent_senders_cannot_both_post(cfg):
    started = threading.Event(); release = threading.Event(); calls = []; output = []
    def blocking(_):
        started.set()
        assert release.wait(10)
        class OK:
            status_code = 200
            def json(self): return {'success': True}
        return OK()
    thread = threading.Thread(target=lambda: output.append(client(cfg, calls, blocking).send_prepared_alarms(prepared())))
    thread.start()
    try:
        assert started.wait(10)
        second = client(cfg, calls).send_prepared_alarms(prepared())
        assert second['backend_errors'] == 1 and len(calls) == 1
    finally:
        release.set(); thread.join(10)
    assert output[0]['sent_ok'] == 1
    assert client(cfg, calls).send_prepared_alarms(prepared())['attempted'] == 0


def test_process_death_releases_sender_lock(cfg):
    path = Path(cfg.delivery_state_path)
    lock = path.with_name(path.name + '.' + scope_key(cfg) + '.lock')
    code = 'from pathlib import Path; from openvas_pull.delivery import sender_lock; import sys,time\nwith sender_lock(Path(sys.argv[1])):\n print("LOCKED",flush=True)\n time.sleep(30)'
    process = subprocess.Popen([sys.executable, '-u', '-c', code, str(lock)], stdout=subprocess.PIPE, text=True)
    try:
        assert process.stdout.readline().strip() == 'LOCKED'
        assert client(cfg, []).send_prepared_alarms(prepared())['backend_errors'] == 1
    finally:
        process.terminate(); process.wait(10); process.stdout.close()
    assert client(cfg, []).send_prepared_alarms(prepared())['sent_ok'] == 1


def test_pending_outbox_drains_even_if_collector_is_down(cfg, tmp_path, clock):
    from openvas_pull.scheduler import run_service
    calls = []
    def fail(_): raise TimeoutError('offline')
    client(cfg, calls, fail).send_prepared_alarms(prepared())
    clock[0] += 2
    class Down:
        def collect(self, **kwargs): raise ValueError('GMP unavailable')
    # Patch only the sender transport. Scheduler still executes the real outbox.
    from unittest.mock import patch
    def post(self, alarm):
        calls.append(alarm)
        return {'success': True, 'http_status': 200}
    with patch.object(BackendAlarmClient, '_post_snapshot', post):
        assert run_service(replace(cfg, payload_dir=str(tmp_path/'payloads')), Down(), once=True) is False
    with sqlite3.connect(cfg.delivery_state_path) as db:
        assert db.execute("SELECT count(*) FROM snapshot_events WHERE status='pending'").fetchone()[0] == 0


def test_partial_snapshot_never_enqueues_or_changes_checkpoint(cfg):
    calls = []; c = client(cfg, calls)
    c.send_prepared_alarms(prepared(0), complete_snapshot=False, snapshot_started_at=30)
    c.send_prepared_alarms(prepared(), complete_snapshot=False, snapshot_started_at=20)
    r = c.send_prepared_alarms(prepared(2), complete_snapshot=True, snapshot_started_at=10)
    assert r['queued']['new'] == 1 and r['sent_ok'] == 2
    assert len(calls) == 1 and len(calls[0]['alarms']) == 2


def test_uncertain_ack_is_retried_instead_of_losing_alarm(cfg, monkeypatch):
    from openvas_pull.delivery import Outbox
    original = Outbox.acknowledge
    def broken_ack(*args): raise OSError('simulated disk failure after HTTP success')
    calls = []
    monkeypatch.setattr(Outbox, 'acknowledge', broken_ack)
    assert client(cfg, calls).send_prepared_alarms(prepared())['backend_errors'] == 1
    monkeypatch.setattr(Outbox, 'acknowledge', original)
    assert client(cfg, calls).send_prepared_alarms(prepared())['sent_ok'] == 1
    assert len(calls) == 2  # HTTP + SQLite cannot be committed atomically together.


def test_pending_context_preserves_original_occurrences(cfg):
    p = prepared()
    contexts = [{'asset_id':'asset','vulnerability_id':'0','occurrences':[{'port':'443/tcp','severity':'critical','cvss_score':9.8,'cves':[]}]}]
    def fail(_): raise TimeoutError('offline')
    c = client(cfg, [], fail)
    c.send_prepared_alarms(p, findings=contexts)
    contexts[0]['occurrences'][0]['port'] = '80/tcp'
    c.send_prepared_alarms(p, findings=contexts)
    with sqlite3.connect(cfg.delivery_state_path) as db:
        rows = db.execute('SELECT context FROM snapshot_events ORDER BY id').fetchall()
        assert [json.loads(r[0])[0]['occurrences'][0]['port'] for r in rows] == ['443/tcp','80/tcp']


def test_operator_controls_never_post_but_enable_targeted_retry_and_resend(cfg, clock):
    calls = []
    def fail(_): raise TimeoutError('offline')
    client(cfg, calls, fail).send_prepared_alarms(prepared())
    base = [sys.executable,'tools/delivery_state.py','--db',cfg.delivery_state_path]
    stats = json.loads(subprocess.check_output([*base,'stats'],text=True))
    assert stats['events'][0]['status']=='pending'
    args = ['--scope',scope_key(cfg)]
    action = json.loads(subprocess.check_output([*base,'retry',*args],text=True))
    assert action['backend_posts']==0 and action['changed_rows']==1
    assert client(cfg,calls).send_prepared_alarms(prepared())['sent_ok']==1
    subprocess.check_output([*base,'force-next-snapshot',*args],text=True)
    result = client(cfg,calls).send_prepared_alarms(prepared())
    assert result['queued']['changed']==1 and result['sent_ok']==1


def test_duplicate_input_fails_closed(cfg):
    from copy import deepcopy
    p = prepared(); p['alarms'].append(deepcopy(p['alarms'][0]))
    calls=[]
    assert client(cfg,calls).send_prepared_alarms(p)['backend_errors']==1
    assert calls == []
    with sqlite3.connect(cfg.delivery_state_path) as db:
        assert db.execute('SELECT count(*) FROM snapshot_events').fetchone()[0]==0


def test_unsupported_schema_fails_without_resetting_state(cfg):
    with sqlite3.connect(cfg.delivery_state_path) as db:
        db.execute('CREATE TABLE schema_version(version INTEGER)')
        db.execute('INSERT INTO schema_version VALUES(999)')
    calls=[]
    assert client(cfg,calls).send_prepared_alarms(prepared())['backend_errors']==1
    assert not calls
    with sqlite3.connect(cfg.delivery_state_path) as db:
        assert db.execute('SELECT version FROM schema_version').fetchone()[0]==999


def test_ack_survives_a_real_process_restart(cfg, tmp_path):
    payload = tmp_path/'prepared.json'
    payload.write_text(json.dumps(prepared()))
    code = '''import json,sys
from openvas_pull.config import Settings
from openvas_pull.backend_client import BackendAlarmClient
c=BackendAlarmClient(Settings(gvm_host='offline',gvm_port=1,gvm_user='dummy',gvm_password='dummy',backend_enabled=True,delivery_state_path=sys.argv[1]))
c._post_snapshot=lambda alarm: {'success':True,'http_status':200}
r=c.send_prepared_alarms(json.load(open(sys.argv[2])))
print(json.dumps({'attempted':r['attempted'],'pending':r['pending_total']}))
'''
    command=[sys.executable,'-c',code,cfg.delivery_state_path,str(payload)]
    assert json.loads(subprocess.check_output(command,text=True))=={'attempted':1,'pending':0}
    assert json.loads(subprocess.check_output(command,text=True))=={'attempted':0,'pending':0}


def test_retry_preserves_exact_snapshot_payload_and_id(cfg, clock):
    calls=[]
    def fail(_): raise TimeoutError('lost response')
    client(cfg,calls,fail).send_prepared_alarms(prepared(3))
    clock[0] += 2
    result=client(cfg,calls).send_prepared_alarms(prepared(0), complete_snapshot=False)
    assert result['snapshots_sent']==1 and calls[0]==calls[1]


def test_legacy_pending_migration_blocks_without_losing_records(cfg):
    with sqlite3.connect(cfg.delivery_state_path) as db:
        db.executescript("CREATE TABLE schema_version(version INTEGER); INSERT INTO schema_version VALUES(1); CREATE TABLE events(status TEXT,payload TEXT); INSERT INTO events VALUES('pending','original');")
    calls=[]
    assert client(cfg,calls).send_prepared_alarms(prepared())['backend_errors']==1
    assert calls==[]
    with sqlite3.connect(cfg.delivery_state_path) as db:
        assert db.execute('SELECT payload FROM events').fetchone()[0]=='original'
        assert db.execute('SELECT version FROM schema_version').fetchone()[0]==1


def test_legacy_acked_migration_keeps_audit_and_sends_first_full_snapshot(cfg):
    with sqlite3.connect(cfg.delivery_state_path) as db:
        db.executescript("CREATE TABLE schema_version(version INTEGER); INSERT INTO schema_version VALUES(1); CREATE TABLE events(status TEXT,payload TEXT); INSERT INTO events VALUES('acked','audit');")
    calls=[]
    assert client(cfg,calls).send_prepared_alarms(prepared(3))['snapshots_sent']==1
    with sqlite3.connect(cfg.delivery_state_path) as db:
        assert db.execute('SELECT payload FROM events').fetchone()[0]=='audit'
        assert db.execute('SELECT version FROM schema_version').fetchone()[0]==2


def test_complete_snapshots_100_to_105_to_70_include_all_remaining(cfg):
    from copy import deepcopy
    calls=[]; c=client(cfg,calls); p=prepared(100)
    c.send_prepared_alarms(p)
    assert c.send_prepared_alarms(deepcopy(p))['attempted']==0
    for alarm in p['alarms'][:5]: alarm['cvss_score']=10.0
    c.send_prepared_alarms(p)
    c.send_prepared_alarms(prepared(105))
    c.send_prepared_alarms(prepared(70))
    assert [len(p['alarms']) for p in calls]==[100,100,105,70]
    assert len({p['snapshot_id'] for p in calls})==4


def test_invalid_findings_never_become_empty_complete_snapshot(cfg):
    c=client(cfg,[])
    p=c.prepare_filtered_findings({'findings':'invalid'})
    assert p['validation_errors']==1
    assert c.send_prepared_alarms(p)['attempted']==0


def test_snapshot_file_is_exact_wire_envelope(cfg,tmp_path):
    from openvas_pull.storage import persist_cycle_payloads
    p=prepared(2); calls=[]
    client(cfg,calls).send_prepared_alarms(p)
    paths=persist_cycle_payloads(str(tmp_path/'artifacts'),None,None,p,{})
    assert json.loads(Path(paths['snapshot_request']).read_text(encoding='utf-8'))==calls[0]
