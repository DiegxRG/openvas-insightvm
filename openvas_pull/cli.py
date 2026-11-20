import argparse
import logging
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from openvas_pull.backend_client import BackendAlarmClient
from openvas_pull.storage import write_json
from openvas_pull.config import load_settings
from openvas_pull.client import OpenVASClient
from openvas_pull.collector import OpenVASCollector
from openvas_pull.logging_setup import setup_logging
from openvas_pull.scheduler import run_service


def main():
    parser = argparse.ArgumentParser(description='OpenVAS a MiFibra; solo altas y criticas')
    parser.add_argument('--env-file', default='.env')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--once', action='store_true')
    mode.add_argument('--retry-pending', action='store_true', help='Reintentar solo SQLite, sin consultar GMP ni crear snapshots')
    parser.add_argument('--no-backend', action='store_true',
                        help='Recolectar sin enviar ni reintentar al backend, incluso si .env lo habilita')
    args = parser.parse_args()
    try:
        settings = load_settings(args.env_file)
    except (ValueError, OSError) as exc:
        print(f'Error de configuración: {exc}', file=sys.stderr)
        raise SystemExit(2)
    if args.no_backend:
        settings = replace(settings, backend_enabled=False)
    if args.retry_pending:
        setup_logging(settings.log_level, str(Path(settings.log_file).with_name('retry.log')))
        result = BackendAlarmClient(settings).retry_pending()
        new_reviews = result.get('new_reviews', 0)
        if result.get('attempted') or result.get('backend_errors') or result.get('conflicts') or new_reviews:
            logging.getLogger(__name__).info('Pending retry attempted=%s sent_ok=%s pending=%s review=%s errors=%s replays=%s',
                result.get('attempted', 0), result.get('sent_ok', 0), result.get('pending_total', 0),
                result.get('review_total', 0), result.get('backend_errors', 0), result.get('replayed_snapshots', 0))
            write_json(Path(settings.payload_dir)/'retry_latest.meta.json',
                       {'started_at': datetime.now(timezone.utc).isoformat(), 'backend': result})
        if result.get('backend_errors') or result.get('conflicts') or new_reviews:
            raise SystemExit(1)
        return
    setup_logging(settings.log_level, settings.log_file)
    logging.getLogger(__name__).info('OpenVAS iniciado; severidades=%s backend_enabled=%s', settings.severities, settings.backend_enabled)
    try:
        success = run_service(settings, OpenVASCollector(OpenVASClient(settings)), once=args.once)
        if args.once and not success:
            raise SystemExit(1)
    except KeyboardInterrupt:
        pass
