"""Exercise persistent dedup on saved JSON, using only an in-memory fake backend."""
import argparse
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from openvas_pull.backend_client import BackendAlarmClient
from openvas_pull.config import Settings


def run(prepared_path, findings_path, output):
    if output.exists():
        raise ValueError('Output must be a new directory so prior acknowledgements are never reused')
    prepared = json.loads(prepared_path.read_text(encoding='utf-8'))
    findings = json.loads(findings_path.read_text(encoding='utf-8'))['findings']
    output.mkdir(parents=True)
    cfg = Settings(gvm_host='saved-json-only',gvm_port=1,gvm_user='test',gvm_password='unused',
                   backend_url='https://backend-simulated.invalid/alarms',backend_enabled=True,
                   delivery_state_path=str(output/'simulated.sqlite3'),delivery_batch_size=100)
    requests = []
    class Reply:
        status_code = 200
        def json(self): return {'success':True}
    def client():
        c = BackendAlarmClient(cfg)
        def fake_post(url, **kwargs):
            assert url == cfg.backend_url
            assert len(kwargs['json']) == 13
            requests.append(deepcopy(kwargs['json']))
            return Reply()
        c.session.post = fake_post
        return c
    def send(p, fs):
        return client().send_prepared_alarms(p,findings=fs,complete_snapshot=True)
    started = time.monotonic()
    first = send(prepared,findings)
    second = send(prepared,findings)
    assert first['sent_ok']==len(prepared['alarms']) and second['attempted']==0
    assert requests == prepared['alarms']  # No backend contract changes.
    updated = deepcopy(prepared); contexts = deepcopy(findings)
    assert len(updated['alarms']) >= 4
    updated['alarms'][0]['cves'] += ', CVE-2099-10001'
    updated['alarms'][1]['vulnerability_title'] += ' [controlled change]'
    contexts[2].setdefault('occurrences',[]).append({'port':'65000/tcp','severity':'critical','cvss_score':10.0,'cves':[]})
    extra = deepcopy(updated['alarms'][3])
    extra.update(asset_id='synthetic-new',finding_id='synthetic-new_controlled',vulnerability_id='controlled',severity='Critical',cvss_score=10.0)
    updated['alarms'].append(extra)
    third = send(updated,contexts)
    assert third['queued']['new']==1 and third['queued']['changed']==3 and third['sent_ok']==4
    assert send(updated,contexts)['attempted']==0
    # Complete absence/reappearance re-delivers; no closure payload is invented.
    reduced = deepcopy(updated); reduced['alarms'] = reduced['alarms'][:-1]
    assert send(reduced,contexts)['attempted']==0
    reappeared = send(updated,contexts)
    assert reappeared['queued']['reappeared']==1 and reappeared['sent_ok']==1
    result={'input_alarms':len(prepared['alarms']),'first_sent':first['sent_ok'],
            'second_attempted':second['attempted'],'new_critical_sent':1,'changed_sent':3,
            'repeat_changes_attempted':0,'reappeared_sent':1,'pending_total':reappeared['pending_total'],
            'wire_contract_unchanged':True,'transport':'in_memory_fake_backend','real_backend_posts':0,
            'seconds':round(time.monotonic()-started,3)}
    (output/'summary.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared',type=Path,required=True)
    parser.add_argument('--findings',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args()
    print(json.dumps(run(a.prepared,a.findings,a.output),indent=2))


if __name__=='__main__':
    main()
