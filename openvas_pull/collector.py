from datetime import datetime, timezone
import math
import re
import logging

from openvas_pull.models import normalize_severity
from openvas_pull.client import OpenVASRequestError


def alarm_date(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        return None


class OpenVASCollector:
    def __init__(self, client):
        self.client = client
        self.pagination_stats = []

    def pages(self, fetch, tag, page_size, context='listado'):
        seen = set()
        total_bytes = 0
        total_results = 0
        for page in range(self.client.settings.max_pages):
            try:
                root, raw = fetch(page * page_size + 1, page_size)
            except OpenVASRequestError as exc:
                raise OpenVASRequestError(f'{context}, pagina={page + 1}: {exc}', retryable=exc.retryable) from exc
            page_bytes = len(raw.encode('utf-8'))
            total_bytes += page_bytes
            nodes = root.findall(tag) if tag == 'task' else root.findall('.//' + tag)
            total_results += len(nodes)
            stat = {'context': context, 'page': page + 1, 'page_bytes': page_bytes,
                    'transfer_bytes': total_bytes, 'page_results': len(nodes), 'results_fetched': total_results}
            if tag == 'results/result':
                buckets = {}
                for node in nodes:
                    try:
                        score = float(node.findtext('severity', ''))
                        label = normalize_severity(score) if math.isfinite(score) and 0 <= score <= 10 else 'unknown'
                    except ValueError:
                        label = 'unknown'
                    buckets[label] = buckets.get(label, 0) + 1
                stat['received_severities'] = buckets
            stat['request_seconds'] = getattr(self.client, 'last_request_stats', {}).get('duration_seconds')
            if getattr(self.client, 'last_request_stats', {}).get('result_filter'):
                stat['requested_filter'] = self.client.last_request_stats['result_filter']
            self.pagination_stats.append(stat)
            logging.getLogger(__name__).info('pagination=%s', stat)
            if page_bytes > self.client.settings.report_max_kb * 1024:
                raise ValueError(f'{context}, pagina={page + 1}: respuesta de {page_bytes} bytes supera '
                                 f'OPENVAS_REPORT_MAX_KB={self.client.settings.report_max_kb}')
            if total_bytes > self.client.settings.pagination_max_kb * 1024:
                raise ValueError(f'{context}, pagina={page + 1}: trafico acumulado de {total_bytes} bytes supera '
                                 f'OPENVAS_PAGINATION_MAX_KB={self.client.settings.pagination_max_kb}')
            if len(nodes) > page_size:
                raise OpenVASRequestError(f'{context}, pagina={page + 1}: GMP no respeto rows={page_size}; recibidos={len(nodes)}')
            if tag == 'results/result' and getattr(self.client, 'enforce_remote_filter', False):
                unexpected = set(stat['received_severities']) - set(self.client.settings.severities)
                if unexpected:
                    raise OpenVASRequestError(f'{context}, pagina={page + 1}: GMP devolvio severidades fuera del filtro: {sorted(unexpected)}')
            signature = tuple(node.get('id') or ET_signature(node) for node in nodes)
            if nodes and signature in seen:
                raise ValueError(f'{context}, pagina={page + 1}: GMP repitió una página; captura incompleta')
            seen.add(signature)
            yield nodes, raw, root
            if len(nodes) < page_size:
                return
        raise ValueError(f'{context}: se alcanzó GVM_MAX_PAGES; captura incompleta')

    def collect(self, page_size, allowed_severities=None):
        settings = self.client.settings
        allowed = set(allowed_severities or ('critical', 'high')) & {'critical', 'high'}
        findings, assets, raw_reports, diagnostics = {}, {}, {}, []
        tasks = []
        tasks_xml = []
        self.pagination_stats = []
        with self.client:
            for nodes, raw, _ in self.pages(self.client.get_tasks, 'task', page_size, context='tareas'):
                tasks.extend(nodes)
                tasks_xml.append(raw)
            for task in tasks:
                task_id = task.get('id', '')
                if settings.task_ids and task_id not in settings.task_ids:
                    continue
                report = task.find('last_report/report')
                if report is None or not report.get('id'):
                    continue
                report_id = report.get('id')
                report_pages = []
                raw_reports[report_id] = report_pages
                for nodes, raw, root in self.pages(
                    lambda first, rows: self.client.get_report(report_id, first, rows), 'results/result', page_size,
                    context=f'task_id={task_id} report_id={report_id}'
                ):
                    report_pages.append(raw)
                    status = root.findtext('.//report/scan_run_status') or report.findtext('scan_run_status')
                    if status != 'Done':
                        diagnostics.append({'report_id': report_id, 'reason': 'report_not_completed', 'status': status})
                        break
                    scan_date = root.findtext('.//report/scan_end') or report.findtext('scan_end')
                    for node in nodes:
                        finding = self.normalize(node, scan_date, diagnostics)
                        if finding is None or finding['severity'] not in allowed:
                            continue
                        key = (finding['asset_id'], finding['vulnerability_id'])
                        finding['task_id'], finding['report_id'] = task_id, report_id
                        finding['port'] = node.findtext('port', '')
                        if key in findings:
                            existing = findings[key]
                            cves = sorted(set(existing['cves'] + finding['cves']))
                            occurrences = existing['occurrences']
                            # Prefer the latest scan, then the highest score on ties.
                            if (finding['fechaalarma'], finding['cvss_score']) > (existing['fechaalarma'], existing['cvss_score']):
                                findings[key] = finding
                            findings[key]['cves'] = cves
                            findings[key]['occurrences'] = occurrences
                        else:
                            findings[key] = finding
                            finding['occurrences'] = []
                        findings[key]['occurrences'].append({'report_id': report_id, 'task_id': task_id, 'port': finding['port']})
                        assets[finding['asset_id']] = {'id': finding['asset_id'], 'ip': finding['asset_ip'], 'hostname': finding['asset_hostname']}
        return {'assets': list(assets.values()), 'findings': list(findings.values()),
                'meta': {'assets_count': len(assets), 'findings_count': len(findings), 'diagnostics': diagnostics,
                         'allowed_severities': sorted(allowed), 'date_timezone': 'UTC',
                         'pagination': self.pagination_stats},
                'raw_api': {'tasks': tasks_xml, 'reports': raw_reports}}

    def normalize(self, node, scan_date, diagnostics):
        host = node.find('host')
        ip = (host.text or '').strip() if host is not None else ''
        oid = node.find('nvt').get('oid', '') if node.find('nvt') is not None else ''
        title = node.findtext('name') or node.findtext('nvt/name')
        try:
            score = float(node.findtext('severity', ''))
        except ValueError:
            score = None
        date = alarm_date(node.findtext('creation_time')) or alarm_date(scan_date)
        if not ip or not oid or not title or score is None or not math.isfinite(score) or not 0 <= score <= 10 or not date:
            diagnostics.append({'result_id': node.get('id'), 'reason': 'missing_or_invalid_fields'})
            return None
        # Stable across reports; do not use a result/report UUID as asset identity.
        asset_id = 'openvas:' + ip.lower()
        hostname = host.findtext('hostname') or ip
        cves = []
        for ref in node.findall('nvt/.//ref'):
            if ref.get('type', '').lower() == 'cve':
                cves.extend(re.findall(r'CVE-\d{4}-\d{4,}', ref.get('id', ''), re.I))
        cves.extend(re.findall(r'CVE-\d{4}-\d{4,}', node.findtext('nvt/cve', ''), re.I))
        return {'asset_id': asset_id, 'asset_ip': ip, 'asset_hostname': hostname,
                'vulnerability_id': oid, 'vulnerability_title': title.strip(),
                'severity': normalize_severity(score), 'cvss_score': score,
                'cves': sorted({c.upper() for c in cves}), 'source': 'openvas', 'fechaalarma': date}


def ET_signature(node):
    from xml.etree.ElementTree import tostring
    return tostring(node, encoding='unicode')


def filter_payload_by_severity(payload, allowed_severities):
    allowed = set(allowed_severities) & {'critical', 'high'}
    findings = [f for f in payload.get('findings', []) if f.get('severity') in allowed]
    return {'findings': findings, 'meta': {**payload.get('meta', {}), 'findings_count': len(findings)}}
