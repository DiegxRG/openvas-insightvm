from dataclasses import replace
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

import pytest

from openvas_pull.client import OpenVASRequestError
from openvas_pull.collector import OpenVASCollector
from openvas_pull.config import Settings
from tools import compare_metadata as comparison


FIXTURES = Path(__file__).parent / 'fixtures'


def settings(**kwargs):
    return Settings(gvm_host='offline', gvm_port=1, gvm_user='unused', gvm_password='unused', **kwargs)


def test_large_metadata_is_not_repeated_on_replay_pages(tmp_path):
    source = ET.fromstring((FIXTURES / 'openvas_report.xml').read_bytes())
    # About the size of the XML reported on Nexus. All metadata is outside results.
    report = source.find('.//{urn:gmp}report')
    ET.SubElement(report, '{urn:gmp}large_summary').text = 'x' * 7_500_000
    container = source.find('.//{urn:gmp}results')
    template = ET.tostring(container[0], encoding='unicode')
    container.clear()
    for index in range(501):
        node = ET.fromstring(template)
        node.set('id', str(index))
        container.append(node)
    path = tmp_path / 'large.xml'
    ET.ElementTree(source).write(path, encoding='utf-8')
    outcome = comparison.compare(None, FIXTURES / 'openvas_tasks.xml', [path], tmp_path / 'out')
    assert outcome['passed'] is True
    assert outcome['sizes']['source_files'][str(path)] > 7_500_000
    pages = [p for p in outcome['sizes']['pagination'] if 'report_id=' in p['context']]
    assert [p['page_results'] for p in pages] == [250, 250, 1]
    assert pages[-1]['transfer_bytes'] < 1_000_000
    findings = json.loads((tmp_path / 'out/openvas_filtered.json').read_text())['findings']
    assert len(findings[0]['occurrences']) == 501
    assert len(ET.parse(path).find('.//{urn:gmp}report/{urn:gmp}large_summary').text) == 7_500_000


def test_live_cli_propagates_same_settings_and_disables_backend(tmp_path, monkeypatch):
    cfg = settings(report_max_kb=65536, pagination_max_kb=98304, page_size=2,
                   backend_enabled=True, backend_local='Nexus-test')
    loads = []
    def load(env):
        loads.append(env)
        return cfg
    def capture(env, output, *, settings):
        assert settings.report_max_kb == 65536
        assert settings.pagination_max_kb == 98304
        assert settings.page_size == 2
        assert settings.backend_enabled is False
        return FIXTURES / 'openvas_tasks.xml', [FIXTURES / 'openvas_report.xml']
    monkeypatch.setattr(comparison, 'load_settings', load)
    monkeypatch.setattr(comparison, 'capture_live', capture)
    monkeypatch.setattr(sys, 'argv', ['compare_metadata.py', '--live', '--output', str(tmp_path)])
    with pytest.raises(SystemExit) as result:
        comparison.main()
    assert result.value.code == 0
    assert len(loads) == 1
    prepared = json.loads((tmp_path / 'openvas_prepared_backend.json').read_text())
    assert prepared['alarms'][0]['Local'] == 'Nexus-test'
    info = json.loads((tmp_path / 'comparison.json').read_text())
    assert info['sizes']['report_max_kib'] == 65536


def test_transfer_budget_is_separate_from_response_limit():
    class Client:
        settings = settings(report_max_kb=1, pagination_max_kb=4)
    collector = OpenVASCollector(Client())
    def fetch(first, rows):
        nodes = '<task id="%s"/>' % first if first <= 3 else ''
        raw = '<response><metadata>' + 'x' * 600 + '</metadata>' + nodes + '</response>'
        return ET.fromstring(raw), raw
    pages = list(collector.pages(fetch, 'task', 1, context='tareas'))
    assert len(pages) == 4
    assert collector.pagination_stats[-1]['transfer_bytes'] > 1024
    Client.settings = replace(Client.settings, pagination_max_kb=1)
    with pytest.raises(ValueError, match=r'tareas, pagina=2:.*OPENVAS_PAGINATION_MAX_KB=1'):
        list(collector.pages(fetch, 'task', 1, context='tareas'))


def test_combined_xml_has_its_own_limit(tmp_path):
    cfg = settings(report_max_kb=1, pagination_max_kb=64)
    path = tmp_path / 'too_large.xml'
    path.write_text('<report id="big"><metadata>' + 'x' * 1100 + '</metadata></report>')
    with pytest.raises(ValueError, match='XML combinado.*OPENVAS_REPORT_MAX_KB=1'):
        comparison.XMLFileClient(cfg, FIXTURES / 'openvas_tasks.xml', [path])


def test_failed_capture_records_context_and_never_prepares_backend(tmp_path, monkeypatch):
    class Client:
        def __init__(self, settings): self.settings = settings
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get_tasks(self, first, rows):
            raw = (FIXTURES / 'openvas_tasks.xml').read_text()
            return ET.fromstring(raw), raw
        def get_report(self, report_id, first, rows):
            raw = '<response><metadata>' + 'x' * 1500 + '</metadata></response>'
            return ET.fromstring(raw), raw
    monkeypatch.setattr(comparison, 'OpenVASClient', Client)
    with pytest.raises(ValueError, match='task_id=sample-task report_id=sample-report, pagina=1'):
        comparison.capture_live('unused', tmp_path, settings=settings(report_max_kb=1))
    metrics = json.loads((tmp_path / 'capture_metrics.json').read_text())
    assert metrics['complete'] is False
    assert metrics['pagination'][-1]['page_bytes'] > 1024
    assert not (tmp_path / 'openvas_prepared_backend.json').exists()


def test_error_context_preserves_retry_policy():
    class Client:
        settings = settings()
    def fetch(first, rows):
        raise OpenVASRequestError('denied', retryable=False)
    with pytest.raises(OpenVASRequestError) as result:
        list(OpenVASCollector(Client()).pages(fetch, 'task', 250, context='tareas'))
    assert result.value.retryable is False
    assert 'tareas, pagina=1' in str(result.value)
