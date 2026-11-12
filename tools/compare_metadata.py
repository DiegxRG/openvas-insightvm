"""Compare metadata with INSIGHT's contract; --live reads GMP without backend POSTs."""
import argparse
import ast
import importlib
import json
from pathlib import Path
import re
import sys
from dataclasses import replace

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
        for path in report_paths:
            root = parse_xml(path.read_bytes())
            report = root if root.tag == 'report' else root.find('.//report')
            if report is None or not report.get('id'):
                raise ValueError(f'Report ID missing in {path}')
            self.reports[report.get('id')] = path

    def __enter__(self): return self
    def __exit__(self, *args): pass

    def page(self, path, first, rows, tag):
        root = parse_xml(path.read_bytes())
        for parent in root.iter():
            children = [child for child in parent if child.tag == tag]
            selected = children[first - 1:first - 1 + rows]
            for child in children:
                if child not in selected:
                    parent.remove(child)
        from xml.etree.ElementTree import tostring
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


def capture_live(env_file, output):
    """Read GMP only. This path never invokes a backend send method."""
    from xml.etree.ElementTree import Element, SubElement, ElementTree
    settings = replace(load_settings(env_file), backend_enabled=False)
    payload = OpenVASCollector(OpenVASClient(settings)).collect(settings.page_size, settings.severities)
    directory = output / 'captured_xml'
    directory.mkdir(parents=True, exist_ok=True)
    tasks = Element('get_tasks_response', status='200')
    for page in payload['raw_api']['tasks']:
        for task in parse_xml(page.encode()).findall('task'):
            report = task.find('last_report/report')
            if report is not None and report.get('id') in payload['raw_api']['reports']:
                tasks.append(task)
    task_path = directory / 'tasks.xml'
    ElementTree(tasks).write(task_path, encoding='utf-8', xml_declaration=True)
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
        ElementTree(root).write(path, encoding='utf-8', xml_declaration=True)
        report_paths.append(path)
    if not report_paths:
        raise ValueError('No reports available to compare')
    return task_path, report_paths


def compare(project, tasks, reports, output, synthetic=False):
    expected, reference_path = insight_expected(project)
    settings = Settings(gvm_host='offline', gvm_port=1, gvm_user='unused', gvm_password='unused')
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
    args = parser.parse_args()
    if bool(args.tasks_xml) != bool(args.report_xml):
        parser.error('Provide --tasks-xml and --report-xml together')
    if args.live and args.tasks_xml:
        parser.error('--live cannot be combined with local XML')
    if args.live:
        try:
            args.tasks_xml, args.report_xml = capture_live(args.env_file, args.output)
        except (OpenVASRequestError, ValueError, OSError) as exc:
            print(f'Live capture failed: {exc}', file=sys.stderr)
            raise SystemExit(1)
    synthetic = not args.tasks_xml
    result = compare(args.insight_project, args.tasks_xml or ROOT / 'tests/fixtures/openvas_tasks.xml',
                     args.report_xml or [ROOT / 'tests/fixtures/openvas_report.xml'], args.output, synthetic)
    if args.live:
        result['live_connection_validated'] = True
        result['input_kind'] = 'live_gmp_capture'
        (args.output / 'comparison.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
