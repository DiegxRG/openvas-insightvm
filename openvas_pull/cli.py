import argparse
import logging
import sys
from openvas_pull.config import load_settings
from openvas_pull.client import OpenVASClient
from openvas_pull.collector import OpenVASCollector
from openvas_pull.logging_setup import setup_logging
from openvas_pull.scheduler import run_service


def main():
    parser = argparse.ArgumentParser(description='OpenVAS a MiFibra; solo altas y criticas')
    parser.add_argument('--env-file', default='.env')
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    try:
        settings = load_settings(args.env_file)
    except (ValueError, OSError) as exc:
        print(f'Error de configuración: {exc}', file=sys.stderr)
        raise SystemExit(2)
    setup_logging(settings.log_level, settings.log_file)
    logging.getLogger(__name__).info('OpenVAS iniciado; severidades=%s backend_enabled=%s', settings.severities, settings.backend_enabled)
    try:
        success = run_service(settings, OpenVASCollector(OpenVASClient(settings)), once=args.once)
        if args.once and not success:
            raise SystemExit(1)
    except KeyboardInterrupt:
        pass
