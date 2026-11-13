"""Controlled loopback GMP service. No scanner, SSH, or backend is contacted."""
from dataclasses import replace
import json
from pathlib import Path
import re
import socketserver
import threading
import time
import xml.etree.ElementTree as ET

import pytest

from openvas_pull.client import OpenVASClient, OpenVASRequestError
from openvas_pull.collector import OpenVASCollector
from openvas_pull.config import Settings
from openvas_pull.backend_client import BackendAlarmClient


@pytest.fixture
def gmp_service(monkeypatch):
    monkeypatch.setattr('requests.Session.post', lambda *a, **kw: pytest.fail('Backend POST forbidden'))
    records = []
    for i in range(1300):
        score = [9.0, 10.0][i % 2] if i < 50 else ([7.0, 8.9][i % 2] if i < 200 else [0.0, 3.9, 6.9][i % 3])
        records.append(f'<result id="r{i:04d}"><name>Controlled result {i}</name><host>192.0.2.10</host>'
                       f'<severity>{score}</severity><creation_time>2026-11-13T12:00:00Z</creation_time>'
                       f'<nvt oid="1.3.6.{i}"><description>{"x" * 2000}</description></nvt></result>')
    state = {'ignore_filter': False, 'filters': []}

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            pending = b''
            while True:
                chunk = self.request.recv(65536)
                if not chunk:
                    return
                pending += chunk
                try:
                    command = ET.fromstring(pending)
                except ET.ParseError:
                    continue
                pending = b''
                if command.tag in {'get_version', 'authenticate'}:
                    answer = f'<{command.tag}_response status="200"/>'
                elif command.tag == 'get_tasks':
                    first = int(re.search(r'first=(\d+)', command.get('filter')).group(1))
                    tasks = '<task id="local-task"><last_report><report id="local-report"/></last_report></task>' if first == 1 else ''
                    answer = f'<get_tasks_response status="200">{tasks}</get_tasks_response>'
                elif command.tag == 'get_reports':
                    term = command.get('filter', '')
                    state['filters'].append(term)
                    constraints = re.findall(r'severity([<>])([0-9.]+)', term)
                    first = int(re.search(r'first=(\d+)', term).group(1))
                    rows = int(re.search(r'rows=(\d+)', term).group(1))
                    selected = records
                    if not state['ignore_filter'] and constraints:
                        def matches(record):
                            score = float(ET.fromstring(record).findtext('severity'))
                            checks = [score > float(bound) if operator == '>' else score < float(bound)
                                      for operator, bound in constraints]
                            # GMP combines repeated expressions with OR unless AND is explicit.
                            return all(checks) if ' and ' in term else any(checks)
                        selected = [r for r in selected if matches(r)]
                    results = ''.join(selected[first - 1:first - 1 + rows])
                    answer = '<get_reports_response status="200"><report id="local-report"><report><scan_run_status>Done</scan_run_status><results>' + results + '</results></report></report></get_reports_response>'
                else:
                    answer = '<error status="400"/>'
                self.request.sendall(answer.encode())

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
    with Server(('127.0.0.1', 0), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        worker.start()
        cfg = Settings(gvm_host='127.0.0.1', gvm_port=server.server_address[1], gvm_user='local-test', gvm_password='dummy', backend_enabled=False)
        try:
            yield cfg, state
        finally:
            server.shutdown()
            worker.join(timeout=2)


def test_controlled_download_filters_before_transfer(gmp_service):
    cfg, state = gmp_service
    class OldClient(OpenVASClient):
        enforce_remote_filter = False
        def get_report(self, report_id, first, rows):
            return self.request(f'<get_reports report_id="{report_id}" details="1" filter="first={first} rows={rows} sort=uuid levels=hmlg overrides=1"/>')
    def run(client):
        started = time.monotonic()
        payload = OpenVASCollector(client).collect(cfg.page_size, cfg.severities)
        pages = [p for p in payload['meta']['pagination'] if 'report_id=' in p['context']]
        return payload, {'received_results': pages[-1]['results_fetched'], 'report_pages': len(pages),
                         'report_bytes': pages[-1]['transfer_bytes'], 'alarms': len(payload['findings']),
                         'duration_seconds': round(time.monotonic() - started, 4)}
    old, baseline = run(OldClient(cfg))
    new, optimized = run(OpenVASClient(cfg))
    assert baseline['received_results'] == 1300
    assert optimized['received_results'] == 200
    assert optimized['report_bytes'] < baseline['report_bytes'] * 0.2
    assert optimized['report_pages'] < baseline['report_pages']
    assert {f['vulnerability_id'] for f in old['findings']} == {f['vulnerability_id'] for f in new['findings']}
    assert {f['severity'] for f in new['findings']} == {'critical', 'high'}
    old_prepared = BackendAlarmClient(cfg).prepare_filtered_findings(old)
    new_prepared = BackendAlarmClient(cfg).prepare_filtered_findings(new)
    assert old_prepared == new_prepared
    assert new_prepared['prepared_alarms_count'] == 200
    assert new_prepared['validation_errors'] == 0
    output = Path(__file__).resolve().parents[1] / 'validation/local_controlled'
    output.mkdir(parents=True, exist_ok=True)
    (output / 'prepared_backend.json').write_text(json.dumps(new_prepared, indent=2) + '\n')
    (output / 'summary.json').write_text(json.dumps({'kind': 'synthetic_loopback_gmp', 'backend_posts': 0,
        'external_connections': 0, 'baseline': baseline, 'optimized': optimized,
        'same_eligible_findings': True, 'same_prepared_alarms': True, 'request_filter': state['filters'][-1],
        'limits': 'Local synthetic service validates client behavior, not real GVMD filtering or remote performance.'}, indent=2) + '\n')


def test_server_ignoring_filter_is_rejected(gmp_service):
    cfg, state = gmp_service
    state['ignore_filter'] = True
    with pytest.raises(OpenVASRequestError, match='fuera del filtro'):
        OpenVASCollector(OpenVASClient(cfg)).collect(cfg.page_size, cfg.severities)


def test_implicit_or_range_is_rejected_like_real_gmp(gmp_service):
    cfg, _ = gmp_service
    class ImplicitORClient(OpenVASClient):
        def get_report(self, report_id, first, rows):
            return self.request(f'<get_reports report_id="{report_id}" details="1" filter="first={first} rows={rows} severity&gt;6.9 severity&lt;10.1"/>')
    with pytest.raises(OpenVASRequestError, match='fuera del filtro'):
        OpenVASCollector(ImplicitORClient(cfg)).collect(cfg.page_size, cfg.severities)


@pytest.mark.parametrize('severities,expected', [(('critical',), 50), (('high',), 150)])
def test_individual_severity_ranges(gmp_service, severities, expected):
    cfg, _ = gmp_service
    cfg = replace(cfg, severities=severities)
    payload = OpenVASCollector(OpenVASClient(cfg)).collect(cfg.page_size, cfg.severities)
    assert len(payload['findings']) == expected
    assert {f['severity'] for f in payload['findings']} == set(severities)


def test_total_deadline_stops_trickled_responses(monkeypatch):
    cfg = Settings(gvm_host='unused', gvm_port=1, gvm_user='dummy', gvm_password='dummy', gvm_timeout=120, gvm_request_timeout=3)
    now = [0]
    monkeypatch.setattr('openvas_pull.client.time.monotonic', lambda: now[0])
    class Socket:
        def settimeout(self, timeout): assert 0 < timeout <= 3
        def sendall(self, command): pass
        def recv(self, size):
            now[0] += 2
            return b'<response status="200">' if now[0] == 2 else b' '
    client = OpenVASClient(cfg)
    client.sock = Socket()
    with pytest.raises(OpenVASRequestError, match='GVM_REQUEST_TIMEOUT=3'):
        client.request('<get_version/>')


def test_split_entity_declaration_is_rejected():
    cfg = Settings(gvm_host='unused', gvm_port=1, gvm_user='dummy', gvm_password='dummy')
    class Socket:
        def __init__(self): self.chunks = iter(bytes([c]) for c in b'<!DOCTYPE x [<!ENTITY a "x">]><x>&a;</x>')
        def settimeout(self, timeout): pass
        def sendall(self, command): pass
        def recv(self, size): return next(self.chunks, b'')
    client = OpenVASClient(cfg)
    client.sock = Socket()
    with pytest.raises(OpenVASRequestError, match='Declaraciones XML'):
        client.request('<get_version/>')
