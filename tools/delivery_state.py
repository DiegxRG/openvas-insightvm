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
    parser.add_argument('action', choices=['stats', 'retry', 'force-next-snapshot'])
    parser.add_argument('--scope')
    parser.add_argument('--snapshot-id')
    args = parser.parse_args()
    path = args.db.resolve()
    if not path.is_file():
        parser.error('Delivery database does not exist; dry runs do not create it')
    if args.action == 'stats':
        with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
            stats = db.execute('SELECT scope,status,count(*),max(attempts) FROM snapshot_events GROUP BY scope,status').fetchall()
            print(json.dumps({'events':[{'scope':s,'status':status,'events':n,'max_attempts':a} for s,status,n,a in stats]}, indent=2))
        return
    if not args.scope:
        parser.error('Control actions require --scope')
    with sender_lock(path.with_name(path.name + '.' + args.scope + '.lock')):
        with sqlite3.connect(path, timeout=10) as db:
            if args.action == 'retry':
                sql = "UPDATE snapshot_events SET next_attempt=0 WHERE scope=? AND status='pending'"
                params = [args.scope]
                if args.snapshot_id:
                    sql += ' AND snapshot_id=?'; params.append(args.snapshot_id)
                changed = db.execute(sql, params).rowcount
            else:
                changed = db.execute('UPDATE snapshot_checkpoints SET force_next=1 WHERE scope=?', (args.scope,)).rowcount
            print(json.dumps({'action':args.action,'changed_rows':changed,'backend_posts':0}))


if __name__ == '__main__':
    main()
