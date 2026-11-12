from dataclasses import dataclass
import os
from dotenv import load_dotenv


def flag(name, default=False):
    return os.getenv(name, str(default)).lower() in {'true', '1', 'yes', 'on'}


@dataclass(frozen=True)
class Settings:
    gvm_host: str
    gvm_port: int
    gvm_user: str
    gvm_password: str
    gvm_timeout: int = 30
    page_size: int = 250
    max_pages: int = 200
    report_max_kb: int = 20000
    task_ids: tuple = ()
    interval_seconds: int = 600
    max_retries: int = 3
    retry_backoff_seconds: float = 1.0
    severities: tuple = ('critical', 'high')
    log_level: str = 'INFO'
    log_file: str = 'logs/integration.log'
    payload_dir: str = 'runtime/openvas/artifacts'
    persist_payload_artifacts: bool = True
    persist_raw_api_debug: bool = False
    backend_enabled: bool = False
    backend_url: str = 'https://10.208.232.208/txdxsecure/guarda_alarma.php'
    backend_local: str = 'Txdxsecure'
    backend_alarm_type: str = '1 - Alarma de seguridad'
    backend_timeout: int = 30
    backend_verify_ssl: bool = True


def load_settings(env_file='.env'):
    load_dotenv(env_file, override=True)
    if os.getenv('GVM_TRANSPORT', 'plain') != 'plain' or not flag('GVM_ALLOW_PLAIN_TCP'):
        raise ValueError('Esta conexión requiere GVM_TRANSPORT=plain y GVM_ALLOW_PLAIN_TCP=true')
    requested = tuple(x.strip().lower() for x in os.getenv('ALERT_SEVERITIES', 'critical,high').split(',') if x.strip())
    if not requested or set(requested) - {'critical', 'high'}:
        raise ValueError('ALERT_SEVERITIES solo admite critical,high')
    settings = Settings(
        gvm_host=os.getenv('GVM_HOST', '').strip(),
        gvm_port=int(os.getenv('GVM_PORT', '41000')),
        gvm_user=os.getenv('GVM_USERNAME', ''),
        gvm_password=os.getenv('GVM_PASSWORD', ''),
        gvm_timeout=int(os.getenv('GVM_TIMEOUT', '30')),
        page_size=int(os.getenv('GVM_REPORT_PAGE_SIZE', '250')),
        max_pages=int(os.getenv('GVM_MAX_PAGES', '200')),
        report_max_kb=int(os.getenv('OPENVAS_REPORT_MAX_KB', '20000')),
        task_ids=tuple(x.strip() for x in os.getenv('GVM_TASK_IDS', '').split(',') if x.strip()),
        interval_seconds=int(os.getenv('OPENVAS_POLL_SECONDS', '600')),
        max_retries=int(os.getenv('MAX_RETRIES', '3')),
        retry_backoff_seconds=float(os.getenv('RETRY_BACKOFF_SECONDS', '1')),
        severities=requested,
        log_level=os.getenv('LOG_LEVEL', 'INFO'),
        log_file=os.getenv('LOG_FILE', 'logs/integration.log'),
        payload_dir=os.getenv('OPENVAS_ARTIFACTS_DIR', 'runtime/openvas/artifacts'),
        persist_payload_artifacts=flag('PERSIST_PAYLOAD_ARTIFACTS', True),
        persist_raw_api_debug=flag('PERSIST_RAW_API_DEBUG'),
        backend_enabled=flag('BACKEND_ENABLED'),
        backend_url=os.getenv('BACKEND_URL', Settings.backend_url),
        backend_local=os.getenv('BACKEND_LOCAL', 'Txdxsecure'),
        backend_alarm_type=os.getenv('BACKEND_ALARM_TYPE', '1 - Alarma de seguridad'),
        backend_timeout=int(os.getenv('BACKEND_TIMEOUT', '30')),
        backend_verify_ssl=flag('BACKEND_TLS_VERIFY', True),
    )
    if not all((settings.gvm_host, settings.gvm_user, settings.gvm_password)):
        raise ValueError('Faltan GVM_HOST, GVM_USERNAME o GVM_PASSWORD')
    for field in ('gvm_timeout', 'page_size', 'max_pages', 'report_max_kb', 'interval_seconds', 'max_retries', 'backend_timeout'):
        if getattr(settings, field) <= 0:
            raise ValueError(f'{field} debe ser mayor que cero')
    if not 1 <= settings.gvm_port <= 65535 or settings.retry_backoff_seconds < 0:
        raise ValueError('Puerto o backoff inválido')
    if settings.backend_enabled and not settings.backend_url.strip():
        raise ValueError('BACKEND_URL es obligatorio para enviar')
    return settings
