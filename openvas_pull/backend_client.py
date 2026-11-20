from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import requests

from openvas_pull.config import Settings
from openvas_pull.snapshots import build_snapshot_id

log = logging.getLogger("openvas_pull.backend")


class BackendAlarmClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.session = requests.Session()

    def prepare_filtered_findings(self, filtered_payload: dict[str, Any], snapshot_id: str | None = None) -> dict[str, Any]:
        findings = filtered_payload.get("findings", [])
        malformed = not isinstance(findings, list)
        if not isinstance(findings, list):
            findings = []

        alarms: list[dict[str, Any]] = []
        skipped_findings: list[dict[str, Any]] = []
        validation_errors = int(malformed)

        for finding in findings:
            if not isinstance(finding, dict):
                validation_errors += 1
                continue
            alarm = self._build_alarm_payload(finding)
            if alarm is None:
                validation_errors += 1
                skipped_findings.append(
                    {
                        "success": False,
                        "message": "Missing required fields: servidor/ip/asset_id/vulnerability_id",
                        "finding": finding,
                    }
                )
                continue
            alarms.append(alarm)

        snapshot_id = snapshot_id or build_snapshot_id()
        payload = {
            "snapshot_id": snapshot_id,
            "request_payload": {"snapshot_id": snapshot_id, "alarms": alarms},
            "enabled": self.settings.backend_enabled,
            "total_filtered_findings": len(findings),
            "prepared_alarms_count": len(alarms),
            "validation_errors": validation_errors,
            "alarms": alarms,
        }
        if skipped_findings:
            payload["skipped_findings"] = skipped_findings
        return payload

    def send_filtered_findings(self, filtered_payload: dict[str, Any]) -> dict[str, Any]:
        prepared_payload = self.prepare_filtered_findings(filtered_payload)
        return self.send_prepared_alarms(prepared_payload, findings=filtered_payload.get('findings', []), complete_snapshot=not filtered_payload.get('meta', {}).get('diagnostics'))

    def retry_pending(self) -> dict[str, Any]:
        if not self.settings.backend_enabled:
            return {'enabled': False, 'retry_only': True, 'skipped': True, 'attempted': 0,
                    'backend_errors': 0, 'conflicts': 0, 'details': []}
        from openvas_pull.delivery import deliver
        try:
            return deliver(self, {'alarms': [], 'validation_errors': 0}, retry_only=True)
        except Exception as exc:
            log.exception('Pending-only delivery failed; no collection or fallback')
            return {'enabled': True, 'retry_only': True, 'attempted': 0, 'backend_errors': 1,
                    'conflicts': 0, 'details': [{'success': False, 'message': str(exc)}]}

    def send_prepared_alarms(self, prepared_payload: dict[str, Any], *, findings=None, complete_snapshot=True, snapshot_started_at=None) -> dict[str, Any]:
        if self.settings.backend_enabled:
            from openvas_pull.delivery import deliver
            try:
                return deliver(self, prepared_payload, findings=findings, complete_snapshot=complete_snapshot, snapshot_started_at=snapshot_started_at)
            except Exception as exc:
                log.exception('Durable delivery failed; no untracked fallback')
                return {'enabled': True, 'dedup_enabled': True, 'sent_ok': 0, 'conflicts': 0,
                        'backend_errors': 1, 'validation_errors': prepared_payload.get('validation_errors', 0),
                        'details': [{'success': False, 'message': str(exc)}]}
        return self._disabled_result(prepared_payload)

    def _disabled_result(self, prepared_payload: dict[str, Any]) -> dict[str, Any]:
        alarms = prepared_payload.get("alarms", [])
        if not isinstance(alarms, list):
            alarms = []

        validation_errors = int(prepared_payload.get("validation_errors", 0))
        details: list[dict[str, Any]] = list(prepared_payload.get("skipped_findings", []))
        if not self.settings.backend_enabled:
            return {
                "enabled": False,
                "skipped": True,
                "total_filtered_findings": int(prepared_payload.get("total_filtered_findings", len(alarms))),
                "prepared_alarms": len(alarms),
                "sent_ok": 0,
                "conflicts": 0,
                "validation_errors": validation_errors,
                "backend_errors": 0,
                "details": details,
            }

    def _build_alarm_payload(self, finding: dict[str, Any]) -> dict[str, Any] | None:
        servidor = str(finding.get("asset_hostname") or "").strip()
        ip = str(finding.get("asset_ip") or "").strip()
        asset_id = str(finding.get("asset_id") or "").strip()
        vulnerability_id = str(finding.get("vulnerability_id") or "").strip()
        if not servidor:
            servidor = ip
        if not servidor or not ip or not asset_id or not vulnerability_id:
            return None

        sev = str(finding.get("severity") or "").lower()
        title = str(finding.get("vulnerability_title") or finding.get("title") or "Alarma de seguridad").strip()
        tipo = self.settings.backend_alarm_type
        fecha = str(finding.get("fechaalarma") or "").strip() or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        from openvas_pull.delivery import normalized_cves
        cves = normalized_cves(finding.get("cves"))

        cvss_score = finding.get("cvss_score")
        if cvss_score is None:
            cvss_score = finding.get("cvss")

        finding_id = _build_finding_id(asset_id, vulnerability_id)

        return {
            "finding_id": finding_id,
            "servidor": servidor,
            "ip": ip,
            "TipoAlarma": tipo,
            "Local": self.settings.backend_local,
            "fechaalarma": fecha,
            "asset_id": asset_id,
            "vulnerability_id": vulnerability_id,
            "vulnerability_title": title,
            "severity": _display_severity(sev),
            "cvss_score": cvss_score,
            "cves": cves,
            "source": str(finding.get("source") or "openvas").strip() or "openvas",
        }

    def _post_snapshot(self, snapshot_payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self.session.post(
                self.settings.backend_url,
                json=snapshot_payload,
                timeout=self.settings.backend_timeout,
                verify=self.settings.backend_ca_bundle or self.settings.backend_verify_ssl,
                headers={"Content-Type": "application/json"},
                allow_redirects=False,
            )
        except Exception as exc:
            log.error("Backend connection error: %s", exc)
            retryable = isinstance(exc, (requests.Timeout, TimeoutError, requests.ConnectionError))
            if isinstance(exc, (requests.exceptions.SSLError, requests.exceptions.ProxyError)):
                retryable = False
            return {"success": False, "retryable": retryable, "message": f"Connection error: {exc}",
                    "snapshot_id": snapshot_payload["snapshot_id"]}

        try:
            data = response.json()
        except Exception:
            data = {"success": False, "message": f"Non-JSON backend response HTTP {response.status_code}"}

        if not isinstance(data, dict):
            data = {"success": False, "message": "Invalid backend response format"}

        data["http_status"] = response.status_code
        data["snapshot_id"] = snapshot_payload["snapshot_id"]
        data["retryable"] = response.status_code in {408, 429, 500, 502, 503, 504}
        data.pop('idempotent_replay_confirmed', None)
        if 200 <= response.status_code < 300 and _confirmed_duplicate_snapshot(data, snapshot_payload):
            # Preserve the backend's success=false; the outbox may acknowledge this exact replay.
            data["idempotent_replay_confirmed"] = True
        return data


def _display_severity(value: str) -> str:
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
        "unknown": "Unknown",
    }
    return mapping.get(value, value.title() if value else "Unknown")


def _build_finding_id(asset_id: str, vulnerability_id: str) -> str:
    return f"{asset_id}_{vulnerability_id}"


def _confirmed_duplicate_snapshot(response, payload):
    """Only a complete, exact key-by-key duplicate receipt confirms a replay."""
    if response.get('success') is not False:
        return False
    alarms = payload.get('alarms', [])
    expected = {a.get('finding_id') for a in alarms}
    data = response.get('data')
    if not expected or len(expected) != len(alarms) or not isinstance(data, dict):
        return False
    sid = payload['snapshot_id']
    errors = data.get('errores')
    if data.get('snapshot_id') != sid or data.get('total_alarmas') != len(alarms):
        return False
    if data.get('registros_exitosos', 0) != 0:
        return False
    if not isinstance(errors, list) or len(errors) != len(expected):
        return False
    seen = set()
    for item in errors:
        if not isinstance(item, dict):
            return False
        identity = item.get('finding_id')
        if not isinstance(identity, str) or identity not in expected or identity in seen:
            return False
        message = f"Ya existe un registro con la combinación finding_id='{identity}' y snapshot_id='{sid}'"
        if item.get('error') != message:
            return False
        seen.add(identity)
    return seen == expected

