import xml.etree.ElementTree as ET
import pytest
from openvas_pull.config import Settings
from openvas_pull.client import OpenVASClient, OpenVASRequestError, parse_xml
from openvas_pull.collector import OpenVASCollector
from openvas_pull.backend_client import BackendAlarmClient


def settings(**kwargs):
    return Settings(gvm_host='example', gvm_port=41000, gvm_user='user', gvm_password='secret', **kwargs)


def result(score, rid='r1', port='443/tcp'):
    return f'''<result id="{rid}"><name>Test vulnerability</name><host>10.0.0.1<hostname>server</hostname></host>
    <port>{port}</port><severity>{score}</severity><creation_time>2026-11-12T10:00:00Z</creation_time>
    <nvt oid="1.2.3"><refs><ref type="cve" id="CVE-2026-1234"/></refs></nvt></result>'''


class FakeClient:
    settings = settings()
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def get_tasks(self, first, rows):
        xml = '<get_tasks_response><task id="t1"><last_report><report id="rep"/></last_report></task></get_tasks_response>'
        return ET.fromstring(xml), xml
    def get_report(self, rid, first, rows):
        results = result(9.8) + result(7.5, 'r2', '80/tcp') + result(6.9, 'r3') + result(0, 'r4')
        xml = '<get_reports_response><report><report><scan_run_status>Done</scan_run_status><results>' + results + '</results></report></report></get_reports_response>'
        return ET.fromstring(xml), xml


def test_collection_filters_and_consolidates():
    payload = OpenVASCollector(FakeClient()).collect(250, ('critical', 'high'))
    assert len(payload['findings']) == 1
    finding = payload['findings'][0]
    assert finding['severity'] == 'critical'
    assert finding['cvss_score'] == 9.8
    assert len(finding['occurrences']) == 2
    client = BackendAlarmClient(settings())
    alarm = client.prepare_filtered_findings(payload)['alarms'][0]
    assert set(alarm) == {'finding_id', 'servidor', 'ip', 'TipoAlarma', 'Local', 'fechaalarma', 'asset_id', 'vulnerability_id', 'vulnerability_title', 'severity', 'cvss_score', 'cves', 'source'}
    assert alarm['source'] == 'openvas'
    assert alarm['cves'] == 'CVE-2026-1234'
    assert alarm['finding_id'] == 'openvas:10.0.0.1_1.2.3'


@pytest.mark.parametrize('score,label', [(6.9,'medium'), (7,'high'), (8.9,'high'), (9,'critical'), (10,'critical')])
def test_severity_boundaries(score, label):
    f = OpenVASCollector(FakeClient()).normalize(ET.fromstring(result(score)), None, [])
    assert f['severity'] == label


@pytest.mark.parametrize('score', ['nan', 'inf', '-1', '11', ''])
def test_invalid_scores_are_rejected(score):
    diagnostics = []
    assert OpenVASCollector(FakeClient()).normalize(ET.fromstring(result(score)), None, diagnostics) is None
    assert diagnostics


def test_disabled_backend_never_posts():
    client = BackendAlarmClient(settings())
    client.session.post = lambda *a, **kw: pytest.fail('Unexpected POST')
    assert client.send_filtered_findings(OpenVASCollector(FakeClient()).collect(250))['skipped'] is True


def test_backend_posts_each_alarm_and_handles_conflict():
    client = BackendAlarmClient(settings(backend_enabled=True))
    calls = []
    class Response:
        status_code = 200
        def json(self): return {'success': False, 'message': 'Ya existe un registro activo'}
    def post(url, **kwargs):
        calls.append(kwargs['json'])
        return Response()
    client.session.post = post
    payload = OpenVASCollector(FakeClient()).collect(250)
    assert client.send_filtered_findings(payload)['conflicts'] == 1
    assert len(calls) == 1 and 'alarms' not in calls[0]


def test_repeated_page_fails_instead_of_sending_partial_data():
    collector = OpenVASCollector(FakeClient())
    with pytest.raises(ValueError, match='repitió'):
        list(collector.pages(collector.client.get_tasks, 'task', 1))


def test_xml_namespaces_and_entities():
    assert parse_xml(b'<x xmlns="urn:gmp"><result/></x>').find('result') is not None
    with pytest.raises(OpenVASRequestError):
        parse_xml(b'<!DOCTYPE x [<!ENTITY a "test">]><x>&a;</x>')


def test_fragmented_and_selfclosing_response():
    class Socket:
        def __init__(self): self.chunks = iter([b'<get_version_response sta', b'tus="200"/>'])
        def settimeout(self, timeout): pass
        def sendall(self, command): pass
        def recv(self, size): return next(self.chunks, b'')
    client = OpenVASClient(settings())
    client.sock = Socket()
    root, _ = client.request('<get_version/>')
    assert root.get('status') == '200'


def test_unfinished_report_is_not_used():
    client = FakeClient()
    original = client.get_report
    def get_report(*args):
        _, xml = original(*args)
        xml = xml.replace('Done', 'Running')
        return ET.fromstring(xml), xml
    client.get_report = get_report
    assert OpenVASCollector(client).collect(250)['findings'] == []


def test_multiple_pages_are_fully_consumed():
    collector = OpenVASCollector(FakeClient())
    calls = []
    def fetch(first, rows):
        calls.append(first)
        entries = '<task id="a"/>' if first == 1 else ''
        xml = '<get_tasks_response>' + entries + '</get_tasks_response>'
        return ET.fromstring(xml), xml
    pages = list(collector.pages(fetch, 'task', 1))
    assert calls == [1, 2]
    assert sum(len(nodes) for nodes, _, _ in pages) == 1


def test_failed_cycle_records_failure_and_returns_false(tmp_path):
    import json
    from openvas_pull.scheduler import run_service
    class BrokenCollector:
        def collect(self, **kwargs): raise ValueError('incomplete')
    cfg = settings(payload_dir=str(tmp_path))
    assert run_service(cfg, BrokenCollector(), once=True) is False
    assert json.loads((tmp_path / 'run_latest.meta.json').read_text())['success'] is False
    assert not (tmp_path / 'prepared_backend_latest.json').exists()


def test_capture_exports_reusable_xml_and_forces_backend_disabled(tmp_path, monkeypatch):
    from pathlib import Path
    from tools import compare_metadata as comparison
    fixtures = Path(__file__).parent / 'fixtures'
    monkeypatch.setattr(comparison, 'load_settings', lambda _: settings(backend_enabled=True))
    def client_factory(cfg):
        assert cfg.backend_enabled is False
        return comparison.XMLFileClient(cfg, fixtures / 'openvas_tasks.xml', [fixtures / 'openvas_report.xml'])
    monkeypatch.setattr(comparison, 'OpenVASClient', client_factory)
    tasks, reports = comparison.capture_live('unused', tmp_path)
    replay = comparison.XMLFileClient(settings(), tasks, reports)
    payload = OpenVASCollector(replay).collect(250)
    assert sorted(f['severity'] for f in payload['findings']) == ['critical', 'high']
    assert payload['findings'][1]['cves'] == ['CVE-2026-10003']


@pytest.mark.parametrize('error', [PermissionError(13, 'Access denied'), TimeoutError('timed out'), ConnectionRefusedError(10061, 'Connection refused')])
def test_connection_error_preserves_diagnostic_without_credentials(monkeypatch, error):
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr('openvas_pull.client.socket.create_connection', fail)
    cfg = settings()
    with pytest.raises(OpenVASRequestError) as caught:
        with OpenVASClient(cfg):
            pytest.fail('Unexpected connection')
    message = str(caught.value)
    assert 'example:41000' in message
    assert type(error).__name__ in message
    assert cfg.gvm_password not in message
    assert caught.value.retryable is (not isinstance(error, PermissionError))


def test_standalone_comparison_uses_bundled_insight_reference(tmp_path):
    from pathlib import Path
    from tools.compare_metadata import compare
    fixtures = Path(__file__).parent / 'fixtures'
    result = compare(None, fixtures / 'openvas_tasks.xml', [fixtures / 'openvas_report.xml'], tmp_path, synthetic=True)
    assert result['passed'] is True
    assert result['alarms_count'] == 2
    assert result['field_count'] == 13
    assert result['same_prepared_payload_as_insight_builder'] is None
    assert (tmp_path / 'openvas_prepared_backend.json').is_file()
