from dataclasses import replace
import xml.etree.ElementTree as ET
import pytest

from backend_fixtures import AcceptedSnapshot
from openvas_pull.collector import OpenVASCollector
from openvas_pull.backend_client import BackendAlarmClient
from openvas_pull.config import Settings


def cfg():
    return Settings(gvm_host='offline', gvm_port=1, gvm_user='dummy', gvm_password='dummy', delivery_dedup_enabled=False)


class Source:
    settings = cfg()
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def get_tasks(self, first, rows):
        raw = '<response><task id="t"><last_report><report id="r"/></last_report></task></response>'
        return ET.fromstring(raw), raw
    def get_report(self, report_id, first, rows):
        raw = '''<response><report id="r"><scan_run_status>Done</scan_run_status><results>
        <result id="old-critical"><name>Vulnerability</name><host>192.0.2.1</host><severity>9.8</severity><creation_time>2026-11-01T00:00:00Z</creation_time><port>443/tcp</port><nvt oid="1.2.3"><refs><ref type="cve" id="CVE-2026-10001"/></refs></nvt></result>
        <result id="new-high"><name>Vulnerability</name><host>192.0.2.1</host><severity>7.5</severity><creation_time>2026-11-13T00:00:00Z</creation_time><port>80/tcp</port><nvt oid="1.2.3"><refs><ref type="cve" id="CVE-2026-10002"/></refs></nvt></result>
        </results></report></response>'''
        root = ET.fromstring(raw)
        if getattr(self, 'reverse', False):
            container = root.find('.//results')
            container[:] = list(reversed(list(container)))
        return root, ET.tostring(root, encoding='unicode')


@pytest.mark.parametrize('reverse', [False, True])
def test_later_high_does_not_hide_critical_and_occurrences_keep_evidence(reverse):
    source = Source()
    source.reverse = reverse
    payload = OpenVASCollector(source).collect(250)
    assert len(payload['findings']) == 1
    finding = payload['findings'][0]
    assert finding['severity'] == 'critical' and finding['cvss_score'] == 9.8
    assert finding['cves'] == ['CVE-2026-10001', 'CVE-2026-10002']
    assert sorted((o['result_id'], o['severity'], o['cvss_score']) for o in finding['occurrences']) == [
        ('new-high', 'high', 7.5),
        ('old-critical', 'critical', 9.8)]
    cves_by_result = {o['result_id']: o['cves'] for o in finding['occurrences']}
    assert cves_by_result['old-critical'] == ['CVE-2026-10001']
    assert cves_by_result['new-high'] == ['CVE-2026-10002']
    alarm = BackendAlarmClient(cfg()).prepare_filtered_findings(payload)['alarms'][0]
    assert alarm['severity'] == 'Critical'
    assert len(alarm) == 13


def test_group_identity_is_stable_on_replay_but_client_resends_without_backend_dedup(tmp_path):
    payload = OpenVASCollector(Source()).collect(250)
    second = OpenVASCollector(Source()).collect(250)
    client = BackendAlarmClient(replace(cfg(), backend_enabled=True, delivery_state_path=str(tmp_path/'state.sqlite3')))
    prepared = client.prepare_filtered_findings(payload, snapshot_id='fixed')
    assert prepared == client.prepare_filtered_findings(second, snapshot_id='fixed')
    calls = []
    def post(url, **kwargs):
        calls.append(kwargs['json']['alarms'][0]['finding_id'])
        return AcceptedSnapshot(kwargs['json'])
    client.session.post = post
    assert client.send_prepared_alarms(prepared)['sent_ok'] == 1
    assert client.send_prepared_alarms(prepared)['sent_ok'] == 1
    assert calls[0] == calls[1]


def test_client_classifies_backend_conflict_without_claiming_local_suppression(tmp_path):
    client = BackendAlarmClient(replace(cfg(), backend_enabled=True, delivery_state_path=str(tmp_path/'state.sqlite3')))
    prepared = client.prepare_filtered_findings(OpenVASCollector(Source()).collect(250))
    seen = set()
    class Response:
        status_code = 200
        def json(self):
            return {'success': False, 'message': 'Ya existe un registro activo'}
    def post(url, **kwargs):
        identity = kwargs['json']['alarms'][0]['finding_id']
        response = Response() if identity in seen else AcceptedSnapshot(kwargs['json'])
        seen.add(identity)
        return response
    client.session.post = post
    assert client.send_prepared_alarms(prepared)['sent_ok'] == 1
    replay = client.send_prepared_alarms(prepared)
    assert replay['conflicts'] == 1 and replay['sent_ok'] == 0 and replay['backend_errors'] == 0
