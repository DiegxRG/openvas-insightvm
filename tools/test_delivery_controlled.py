"""Replay saved findings into a fake backend; never connects to GMP or HTTP."""
import argparse
from copy import deepcopy
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
        raise ValueError('Output must be a new directory; never reuse production acknowledgements')
    old = json.loads(prepared_path.read_text(encoding='utf-8'))
    findings = json.loads(findings_path.read_text(encoding='utf-8'))['findings']
    assert len(old['alarms']) == len(findings) and len(findings) >= 5
    output.mkdir(parents=True)
    cfg = Settings(gvm_host='saved-json-only',gvm_port=1,gvm_user='test',gvm_password='unused',
                   backend_url='https://backend-simulated.invalid/alarms',backend_enabled=True,
                   delivery_state_path=str(output/'simulated.sqlite3'))
    requests = []
    class Reply:
        status_code = 200
        def json(self): return {'success': True}
    def client():
        c = BackendAlarmClient(cfg)
        def fake_post(url, **kwargs):
            assert url == cfg.backend_url
            payload = kwargs['json']
            assert set(payload) == {'snapshot_id','alarms'}
            assert all(len(a)==13 and isinstance(a['cves'],list) for a in payload['alarms'])
            requests.append(deepcopy(payload))
            return Reply()
        c.session.post = fake_post
        return c
    def send(fs):
        c=client()
        p=c.prepare_filtered_findings({'findings':fs})
        result=c.send_prepared_alarms(p,findings=fs,complete_snapshot=True)
        return result,p
    started=time.monotonic()
    first,prepared=send(findings)
    assert first['snapshots_sent']==1 and first['sent_ok']==len(findings)
    assert requests[0]==prepared['request_payload']
    assert {a['finding_id'] for a in requests[0]['alarms']}=={a['finding_id'] for a in old['alarms']}
    (output/'openvas_snapshot_request.json').write_text(json.dumps(requests[0],indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    second,_=send(findings)
    assert second['attempted']==0
    updated=deepcopy(findings)
    updated[0]['cvss_score']=10.0 if updated[0]['cvss_score']!=10.0 else 9.9
    cvss,_=send(updated)
    assert cvss['snapshots_sent']==1 and cvss['sent_ok']==len(findings)
    updated[1].setdefault('cves',[]).append('CVE-2099-10001')
    cves,_=send(updated)
    assert cves['snapshots_sent']==1 and cves['sent_ok']==len(findings)
    extra=deepcopy(updated[2])
    extra.update(asset_id='synthetic-new',vulnerability_id='controlled',severity='critical',cvss_score=10.0)
    updated.append(extra)
    added,_=send(updated)
    assert added['snapshots_sent']==1 and added['sent_ok']==len(findings)+1
    assert send(updated)[0]['attempted']==0
    reduced=updated[:-1]
    removed,_=send(reduced)
    assert removed['snapshots_sent']==1 and removed['sent_ok']==len(findings)
    reappeared,_=send(updated)
    assert reappeared['snapshots_sent']==1 and reappeared['sent_ok']==len(findings)+1
    empty,_=send([])
    assert empty['snapshots_sent']==1 and requests[-1]['alarms']==[]
    assert send([])[0]['attempted']==0
    result={'input_alarms':len(findings),'snapshot_sizes':[len(p['alarms']) for p in requests],
            'unchanged_attempted':second['attempted'],'cvss_only_detected':True,'cves_only_detected':True,
            'removal_detected':True,'complete_empty_snapshot_sent':True,
            'pending_total':empty['pending_total'],'contract':'snapshot_id + alarms; 13 fields; cves list',
            'transport':'in_memory_fake_backend','real_backend_posts':0,
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
