from pathlib import Path
import json

import pytest

from openvas_pull import cli
from openvas_pull.config import Settings


@pytest.mark.parametrize('env_enabled', [True, False])
def test_no_backend_overrides_env_and_preserves_artifacts(monkeypatch, tmp_path, env_enabled):
    cfg = Settings(gvm_host='offline', gvm_port=1, gvm_user='test', gvm_password='unused',
                   backend_enabled=env_enabled, delivery_state_path=str(tmp_path/'state.sqlite3'))
    monkeypatch.setattr(cli.sys, 'argv', ['main.py', '--env-file', 'test.env', '--once', '--no-backend'])
    monkeypatch.setattr(cli, 'load_settings', lambda path: cfg)
    monkeypatch.setattr(cli, 'setup_logging', lambda *args: None)
    monkeypatch.setattr(cli, 'OpenVASClient', lambda settings: settings)
    monkeypatch.setattr(cli, 'OpenVASCollector', lambda client: client)
    seen = []
    def run(settings, collector, once):
        seen.append(settings)
        assert settings.backend_enabled is False and collector is settings and once is True
        assert settings.persist_payload_artifacts is True
        return True
    monkeypatch.setattr(cli, 'run_service', run)
    cli.main()
    assert len(seen) == 1 and not Path(cfg.delivery_state_path).exists()


def test_no_backend_keeps_failure_exit_code(monkeypatch):
    cfg = Settings(gvm_host='offline', gvm_port=1, gvm_user='test', gvm_password='unused', backend_enabled=True)
    monkeypatch.setattr(cli.sys, 'argv', ['main.py', '--once', '--no-backend'])
    monkeypatch.setattr(cli, 'load_settings', lambda path: cfg)
    monkeypatch.setattr(cli, 'setup_logging', lambda *args: None)
    monkeypatch.setattr(cli, 'OpenVASClient', lambda settings: settings)
    monkeypatch.setattr(cli, 'OpenVASCollector', lambda client: client)
    monkeypatch.setattr(cli, 'run_service', lambda *args, **kwargs: False)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1


def test_collection_only_runs_real_scheduler_without_http_or_outbox(monkeypatch, tmp_path):
    import requests
    from tools.compare_metadata import XMLFileClient
    fixtures = Path(__file__).parent/'fixtures'
    cfg = Settings(gvm_host='offline', gvm_port=1, gvm_user='test', gvm_password='unused',
                   backend_enabled=True, payload_dir=str(tmp_path/'artifacts'),
                   delivery_state_path=str(tmp_path/'delivery.sqlite3'))
    monkeypatch.setattr(cli.sys, 'argv', ['main.py', '--once', '--no-backend'])
    monkeypatch.setattr(cli, 'load_settings', lambda path: cfg)
    monkeypatch.setattr(cli, 'setup_logging', lambda *args: None)
    monkeypatch.setattr(cli, 'OpenVASClient', lambda settings: XMLFileClient(
        settings, fixtures/'openvas_tasks.xml', [fixtures/'openvas_report.xml']))
    monkeypatch.setattr(requests.Session, 'post', lambda *a, **k: pytest.fail('Unexpected HTTP POST'))
    cli.main()
    output = Path(cfg.payload_dir)
    assert not Path(cfg.delivery_state_path).exists()
    wire = json.loads((output/'snapshot_request_latest.json').read_text(encoding='utf-8'))
    assert set(wire) == {'snapshot_id', 'alarms'} and len(wire['alarms']) == 2
    assert json.loads((output/'run_latest.meta.json').read_text(encoding='utf-8'))['backend']['enabled'] is False
