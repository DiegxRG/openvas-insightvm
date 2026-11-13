"""Inspect/control the local delivery ledger. Never contacts GMP or the backend."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from openvas_pull.delivery import sender_lock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, default=ROOT/'runtime/openvas/delivery.sqlite3')
    parser.add_argument('action', choices=['stats', 'retry', 'resend-next-observation'])
    parser.add_argument('--scope')
    parser.add_argument('--finding-id')
    args = parser.parse_args()
    path = args.db.resolve()
    if not path.is_file():
        parser.error('Delivery database does not exist; dry runs do not create it')
    if args.action == 'stats':
        with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
            stats = db.execute('SELECT scope,status,count(*),max(attempts) FROM events GROUP BY scope,status').fetchall()
            identities = db.execute('SELECT scope,count(*),sum(active) FROM findings GROUP BY scope').fetchall()
            print(json.dumps({'events':[{'scope':s,'status':status,'events':n,'max_attempts':a} for s,status,n,a in stats],
                              'identities':[{'scope':s,'total':n,'active':a} for s,n,a in identities]}, indent=2))
        return
    if not args.scope or not args.finding_id:
        parser.error('Control actions require --scope and --finding-id')
    with sender_lock(path.with_name(path.name + '.' + args.scope + '.lock')):
        with sqlite3.connect(path, timeout=10) as db:
            if args.action == 'retry':
                changed = db.execute("UPDATE events SET next_attempt=0 WHERE scope=? AND finding_id=? AND status='pending'", (args.scope,args.finding_id)).rowcount
            else:
                changed = db.execute('UPDATE findings SET active=0 WHERE scope=? AND finding_id=?', (args.scope,args.finding_id)).rowcount
            print(json.dumps({'action':args.action,'changed_rows':changed,'backend_posts':0}))


if __name__ == '__main__':
    main()
