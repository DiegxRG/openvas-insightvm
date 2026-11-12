"""Compare metadata with INSIGHT's contract; --live reads GMP without backend POSTs."""
import argparse
import ast
import importlib
import json
from pathlib import Path
import re
import sys
from dataclasses import replace
from copy import deepcopy

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from openvas_pull.backend_client import BackendAlarmClient
from openvas_pull.client import OpenVASClient, OpenVASRequestError, parse_xml
from openvas_pull.collector import OpenVASCollector, filter_payload_by_severity
from openvas_pull.config import Settings, load_settings


class XMLFileClient:
    def __init__(self, settings, tasks_path, report_paths):
        self.settings = settings
        self.tasks_path = tasks_path
        self.reports = {}
        self._cached_path = None
        self._cached_root = None
        self.file_sizes = {}
        for path in report_paths:
            root = self.read(path)
            report = root if root.tag == 'report' else root.find('.//report')
            if report is None or not report.get('id'):
                raise ValueError(f'Report ID missing in {path}')
            self.reports[report.get('id')] = path

    def __enter__(self): return self
    def __exit__(self, *args): pass

    def read(self, path):
        if path != self._cached_path:
            size = path.stat().st_size
            self.file_sizes[str(path)] = size
            if size > self.settings.report_max_kb * 1024:
                raise ValueError(f'XML combinado {path}: {size} bytes supera OPENVAS_REPORT_MAX_KB={self.settings.report_max_kb}')
            self._cached_root = parse_xml(path.read_bytes())
            self._cached_path = path
        return self._cached_root

    def page(self, path, first, rows, tag):
        from xml.etree.ElementTree import Element, SubElement, tostring
        source = self.read(path)
        if tag == 'task':
            root = Element('get_tasks_response', status='200')
            root.extend(deepcopy(node) for node in source.findall('task')[first - 1:first - 1 + rows])
        else:
            # Replay only the selected results and metadata used by the collector.
            # Large host/NVT summaries outside results must not recur on every page.
            root = Element('get_reports_response', status='200')
            original = source if source.tag == 'report' else source.find('.//report')
            report = SubElement(root, 'report', id=original.get('id', ''))
            for name in ('scan_run_status', 'scan_end'):
                value = original.findtext('.//' + name)
                if value is not None:
                    SubElement(report, name).text = value
            container = SubElement(report, 'results')
            nodes = source.findall('.//results/result')
            container.extend(deepcopy(node) for node in nodes[first - 1:first - 1 + rows])
        return root, tostring(root, encoding='unicode')

    def get_tasks(self, first, rows):
        return self.page(self.tasks_path, first, rows, 'task')

    def get_report(self, report_id, first, rows):
        if report_id not in self.reports:
            raise ValueError(f'XML missing for report {report_id}')
        return self.page(self.reports[report_id], first, rows, 'result')


def insight_expected(project):
    if project is None:
        path = ROOT / 'tests/fixtures/insight_reference_alarm.json'
        return json.loads(path.read_text(encoding='utf-8')), 'tests/fixtures/insight_reference_alarm.json'
    path = project / 'tests/test_backend_client.py'
    tree = ast.parse(path.read_text(encoding='utf-8-sig'))
    for function in tree.body:
        if isinstance(function, ast.FunctionDef) and function.name == 'test_backend_prepare_filtered_findings_includes_extended_fields':
            for node in ast.walk(function):
                if isinstance(node, ast.Assert) and isinstance(node.test, ast.Compare):
                    for comparator in node.test.comparators:
                        if isinstance(comparator, ast.Dict):
                            return ast.literal_eval(comparator), str(path)
    raise ValueError('Expected INSIGHT alarm example not found')


def capture_live(env_file, output, *, settings=None):
    """Read GMP only. This path never invokes a backend send method."""
    from xml.etree.ElementTree import Element, SubElement, tostring
    settings = replace(settings or load_settings(env_file), backend_enabled=False)
    collector = OpenVASCollector(OpenVASClient(settings))
    metrics = {'response_and_combined_limit_kib': settings.report_max_kb,
               'pagination_transfer_limit_kib': settings.pagination_max_kb,
               'files': [], 'complete': False}
    output.mkdir(parents=True, exist_ok=True)

    def save_metrics(error=None):
        metrics['pagination'] = collector.pagination_stats
        if error is not None:
            metrics['error'] = str(error)
        (output / 'capture_metrics.json').write_text(json.dumps(metrics, indent=2) + '\n', encoding='utf-8')

    def write_xml(root, path, context):
        data = tostring(root, encoding='utf-8', xml_declaration=True)
        metrics['files'].append({'path': str(path), 'bytes': len(data), 'context': context})
        if len(data) > settings.report_max_kb * 1024:
            error = ValueError(f'{context}: XML combinado de {len(data)} bytes supera OPENVAS_REPORT_MAX_KB={settings.report_max_kb}')
            save_metrics(error)
            raise error
        path.write_bytes(data)

    try:
        payload = collector.collect(settings.page_size, settings.severities)
    except (OpenVASRequestError, ValueError, OSError) as exc:
        save_metrics(exc)
        raise
    directory = output / 'captured_xml'
    directory.mkdir(parents=True, exist_ok=True)
    tasks = Element('get_tasks_response', status='200')
    for page in payload['raw_api']['tasks']:
        for task in parse_xml(page.encode()).findall('task'):
            report = task.find('last_report/report')
            if report is not None and report.get('id') in payload['raw_api']['reports']:
                tasks.append(task)
    task_path = directory / 'tasks.xml'
    write_xml(tasks, task_path, 'tareas')
    report_paths = []
    for index, (report_id, pages) in enumerate(payload['raw_api']['reports'].items()):
        root = parse_xml(pages[0].encode())
        container = root.find('.//results')
        if container is None:
            report = root.find('.//report')
            if report is None:
                raise ValueError('Missing report in live GMP response')
            container = SubElement(report, 'results')
        for page in pages[1:]:
            container.extend(parse_xml(page.encode()).findall('.//results/result'))
        path = directory / f'report_{index:04d}.xml'
        write_xml(root, path, f'report_id={report_id}')
        report_paths.append(path)
    if not report_paths:
        save_metrics('No reports available to compare')
        raise ValueError('No reports available to compare')
    metrics['complete'] = True
    save_metrics()
    return task_path, report_paths


def compare(project, tasks, reports, output, synthetic=False, settings=None):
    expected, reference_path = insight_expected(project)
    settings = replace(settings, backend_enabled=False) if settings else Settings(gvm_host='offline', gvm_port=1, gvm_user='unused', gvm_password='unused')
    client = XMLFileClient(settings, tasks, reports)
    payload = OpenVASCollector(client).collect(settings.page_size, settings.severities)
    filtered = filter_payload_by_severity(payload, settings.severities)
    prepared = BackendAlarmClient(settings).prepare_filtered_findings(filtered)
    builder_matches = None
    if project is not None:
        sys.path.insert(0, str(project))
        insight_backend = importlib.import_module('insightvm_pull.backend_client').BackendAlarmClient(settings)
        # Optional deeper comparison when the original project is available.
        builder_matches = prepared == insight_backend.prepare_filtered_findings(filtered)
    schema = []
    for alarm in prepared['alarms']:
        schema.append({
            'finding_id': alarm['finding_id'],
            'missing_fields': sorted(expected.keys() - alarm.keys()),
            'extra_fields': sorted(alarm.keys() - expected.keys()),
            'type_mismatches': {k: {'expected': type(expected[k]).__name__, 'actual': type(alarm[k]).__name__}
                                for k in expected.keys() & alarm.keys() if type(alarm[k]) is not type(expected[k])},
            'valid_date_format': bool(re.fullmatch(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', alarm['fechaalarma'])),
            'allowed_severity': alarm['severity'] in {'High', 'Critical'},
        })
    success = bool(schema) and builder_matches is not False and not prepared['validation_errors'] and all(
        not row['missing_fields'] and not row['extra_fields'] and not row['type_mismatches']
        and row['valid_date_format'] and row['allowed_severity'] for row in schema)
    comparison = {
        'passed': success, 'input_kind': 'synthetic_fixture' if synthetic else 'user_supplied_xml',
        'live_connection_validated': False, 'backend_posts': 0,
        'reference': reference_path, 'reference_kind': 'INSIGHT test example' if project is None else 'INSIGHT test example and actual backend builder',
        'same_prepared_payload_as_insight_builder': builder_matches,
        'comparison_status': 'passed' if success else ('no_eligible_findings' if not schema else 'failed'),
        'alarms_count': len(prepared['alarms']), 'field_count': len(expected), 'schema_checks': schema,
        'diagnostics': payload['meta']['diagnostics'],
        'sizes': {'source_files': client.file_sizes, 'replay_pagination': client.settings.pagination_max_kb,
                  'report_max_kib': settings.report_max_kb, 'pagination': payload['meta']['pagination']},
        'limits': ['Structural compatibility only; scanner connectivity and backend acceptance are not validated.',
                   'OpenVAS dates are UTC; INSIGHT truncates source timestamps without timezone conversion.',
                   'OpenVAS asset_id is namespaced IP and vulnerability_id is NVT OID.'],
    }
    output.mkdir(parents=True, exist_ok=True)
    for name, value in [('comparison.json', comparison), ('insight_reference_alarm.json', expected),
                        ('openvas_filtered.json', filtered), ('openvas_prepared_backend.json', prepared)]:
        (output / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return comparison


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--insight-project', type=Path, help='Optional original INSIGHT project; otherwise use bundled contract example')
    parser.add_argument('--tasks-xml', type=Path)
    parser.add_argument('--report-xml', type=Path, action='append')
    parser.add_argument('--output', type=Path, default=ROOT / 'validation/metadata')
    parser.add_argument('--live', action='store_true', help='Read GMP and compare without sending backend alarms')
    parser.add_argument('--env-file', default=str(ROOT / '.env'))
    parser.add_argument('--report-max-kb', type=int, help='XML limit per response and combined file, in KiB')
    parser.add_argument('--pagination-max-kb', type=int, help='Cumulative transfer budget per task list/report, in KiB')
    args = parser.parse_args()
    if bool(args.tasks_xml) != bool(args.report_xml):
        parser.error('Provide --tasks-xml and --report-xml together')
    if args.live and args.tasks_xml:
        parser.error('--live cannot be combined with local XML')
    try:
        settings = load_settings(args.env_file) if args.live else Settings(gvm_host='offline', gvm_port=1, gvm_user='unused', gvm_password='unused')
        overrides = {name: value for name, value in [('report_max_kb', args.report_max_kb), ('pagination_max_kb', args.pagination_max_kb)] if value is not None}
        if any(value <= 0 for value in overrides.values()):
            parser.error('Size limits must be positive')
        settings = replace(settings, backend_enabled=False, **overrides)
        if args.live:
            args.tasks_xml, args.report_xml = capture_live(args.env_file, args.output, settings=settings)
        synthetic = not args.tasks_xml
        result = compare(args.insight_project, args.tasks_xml or ROOT / 'tests/fixtures/openvas_tasks.xml',
                         args.report_xml or [ROOT / 'tests/fixtures/openvas_report.xml'], args.output, synthetic, settings=settings)
    except (OpenVASRequestError, ValueError, OSError) as exc:
        print(f'Metadata validation failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
    if args.live:
        result['live_connection_validated'] = True
        result['input_kind'] = 'live_gmp_capture'
        (args.output / 'comparison.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
