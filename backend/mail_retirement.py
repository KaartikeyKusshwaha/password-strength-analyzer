"""Offline, backed-up retirement of legacy email-assessment history. No web route."""
import argparse
from contextlib import contextmanager
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
from cryptography.fernet import InvalidToken

from .backups import create_backup,read_backup,read_bounded,memory_snapshot,MAX_BYTES
from .store import Store,canonical,now

ARCHIVE='retired_mail_records'
KINDS={'assets','scans','findings','tasks','investigations','jobs','operations','security_reviews','notifications','watch_runs'}
WORK={'jobs','operations','security_reviews','watch_runs'}
ACTIVE={'pending','queued','running','waiting_unlock','awaiting_confirmation'}
REFS={'asset_id','finding_id','finding_ids','scan_id','operation_id','agent_job','review_id','job_id','watch_id'}


class RetirementError(ValueError):
    pass


def sha(value):return hashlib.sha256(value.encode()).hexdigest()


@contextmanager
def connection(data_dir,write=False):
    path=Path(data_dir).resolve(strict=True)/'sentinelops.db'
    if path.is_symlink() or not path.is_file():raise RetirementError('A regular source database is required.')
    c=sqlite3.connect(path.as_uri()+('?mode=rw' if write else '?mode=ro'),uri=True,timeout=5)
    c.row_factory=sqlite3.Row
    try:
        c.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        yield c
        c.commit()
    except BaseException:
        c.rollback();raise
    finally:c.close()


def references(value):
    found=set()
    if isinstance(value,dict):
        for key,item in value.items():
            if key in REFS:
                if isinstance(item,str):found.add(item)
                elif isinstance(item,list):found.update(v for v in item if isinstance(v,str))
            if key=='snapshot' and isinstance(item,dict):found.update(item)
            found.update(references(item))
    elif isinstance(value,list):
        for item in value:found.update(references(item))
    return found


def opaque_references(value):
    if isinstance(value,str):return {value}
    if isinstance(value,dict):
        result=set(value)
        for item in value.values():result.update(opaque_references(item))
        return result
    if isinstance(value,list):
        result=set()
        for item in value:result.update(opaque_references(item))
        return result
    return set()


def legacy_marker(value):
    if isinstance(value,dict):
        return any(key in {'mail_coverage','message_digest','email_format'} and item is not None or legacy_marker(item) for key,item in value.items())
    return isinstance(value,list) and any(legacy_marker(item) for item in value)


def legacy(kind,value):
    checks=value.get('checks') if isinstance(value.get('checks'),list) else []
    return (kind=='assets' and isinstance(value.get('kind'),str) and value['kind'] in {'inbox','email'} or
            kind in {'scans','findings'} and value.get('kind')=='email' or
            kind=='findings' and re.fullmatch(r'MAIL\d+',str(value.get('rule',''))) is not None or
            kind=='operations' and value.get('action')=='email' or
            kind=='security_reviews' and any(item.get('action')=='email' for item in checks if isinstance(item,dict)) or
            legacy_marker(value))


def select_plan(c,workspace):
    if not re.fullmatch(r'[a-f0-9]{24}',workspace) or not c.execute('SELECT 1 FROM workspaces WHERE id=?',(workspace,)).fetchone():raise RetirementError('Workspace unavailable.')
    size=c.execute('SELECT count(*),coalesce(sum(length(CAST(data AS BLOB))),0) FROM entities WHERE workspace=? AND kind!=?',(workspace,ARCHIVE)).fetchone()
    if size[0]>10000 or size[1]>MAX_BYTES:raise RetirementError('Workspace exceeds the bounded retirement limit.')
    rows=c.execute('SELECT * FROM entities WHERE workspace=? AND kind!=? ORDER BY id',(workspace,ARCHIVE)).fetchall()
    records={row['id']:(dict(row),json.loads(row['data'])) for row in rows}
    if any(not isinstance(value,dict) for row,value in records.values()):raise RetirementError('Unsupported historical record.')
    roots={identifier for identifier,(row,value) in records.items() if row['kind'] in KINDS and legacy(row['kind'],value)}
    inboxes={identifier for identifier in roots if records[identifier][0]['kind']=='assets'}
    edges={identifier:set() for identifier in records}
    for identifier,(row,value) in records.items():
        linked=references(value) if row['kind'] in KINDS else opaque_references(value)
        for other in linked&records.keys():
            # A normal application asset may have unrelated checks. Only retired
            # inbox assets participate in the historical component.
            if records[other][0]['kind']=='assets' and other not in inboxes:continue
            edges[identifier].add(other);edges[other].add(identifier)
    selected=set(roots);front=list(roots)
    while front:
        for other in edges[front.pop()]-selected:selected.add(other);front.append(other)
    opaque=[identifier for identifier in selected if records[identifier][0]['kind'] not in KINDS]
    active=[identifier for identifier in selected if records[identifier][0]['kind'] in WORK and records[identifier][1].get('status') in ACTIVE]
    counts={};collateral={};items=[]
    for identifier in sorted(selected):
        row,value=records[identifier];kind=row['kind'];counts[kind]=counts.get(kind,0)+1
        if identifier not in roots:collateral[kind]=collateral.get(kind,0)+1
        items.append({'id':identifier,'kind':kind,'sha256':sha(row['data']),'reason':'retired_email_feature' if identifier in roots else 'linked_history'})
    manifest={'version':1,'workspace':workspace,'records':items,'counts':counts,'linked_history':collateral,'active_records':len(active),'unsupported_records':len(opaque)}
    return {**manifest,'digest':sha(canonical(manifest))}


def plan(data_dir,workspace):
    with connection(data_dir) as c:return select_plan(c,workspace)


def apply_archive(data_dir,workspace,approved_digest,key_file,backup_output,allow_linked_history=False):
    preview=plan(data_dir,workspace)
    if not isinstance(approved_digest,str) or not hmac.compare_digest(preview['digest'],approved_digest):raise RetirementError('Plan changed. Review a new preview.')
    if preview['active_records'] or preview['unsupported_records']:raise RetirementError('Stop active work or resolve unsupported references before retirement.')
    if preview['linked_history'] and not allow_linked_history:raise RetirementError('Linked history requires explicit scope approval.')
    if not preview['records']:return {'archived':0,'digest':approved_digest,'backup_created':False}
    create_backup(data_dir,key_file,backup_output)
    _,_,database,backup_digest=read_backup(backup_output,key_file)
    with memory_snapshot(database) as snapshot:
        snapshot.row_factory=sqlite3.Row
        if select_plan(snapshot,workspace)['digest']!=approved_digest:raise RetirementError('Backup does not match the approved history. No records were changed.')
    with connection(data_dir,True) as c:
        if select_plan(c,workspace)['digest']!=approved_digest:raise RetirementError('History changed after backup. No records were changed.')
        if hashlib.sha256(read_bounded(backup_output,MAX_BYTES+36)).hexdigest()!=backup_digest:raise RetirementError('Verified backup changed. No records were changed.')
        if not Store.audit(c,workspace)['valid']:raise RetirementError('Audit chain is invalid. No records were changed.')
        for item in preview['records']:
            row=c.execute('SELECT data FROM entities WHERE id=? AND workspace=? AND kind=?',(item['id'],workspace,item['kind'])).fetchone()
            value={'version':1,'id':item['id'],'source_kind':item['kind'],'source_json':row['data'],'source_sha256':item['sha256'],'archive_plan':approved_digest,'backup_sha256':backup_digest,'archived_at':now()}
            changed=c.execute('UPDATE entities SET kind=?,data=? WHERE id=? AND workspace=? AND kind=? AND data=?',(ARCHIVE,canonical(value),item['id'],workspace,item['kind'],row['data'])).rowcount
            if changed!=1:raise RetirementError('History changed during retirement.')
        Store.event(c,workspace,'system:mail-retirement','retired_mail.archived',approved_digest)
    return {'archived':len(preview['records']),'digest':approved_digest,'backup_created':True,'backup_sha256':backup_digest}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir',required=True);parser.add_argument('--workspace',required=True)
    parser.add_argument('--apply',action='store_true');parser.add_argument('--approve-digest')
    parser.add_argument('--backup-key');parser.add_argument('--backup-output')
    parser.add_argument('--allow-linked-history',action='store_true')
    args=parser.parse_args(argv)
    if args.apply and not all((args.approve_digest,args.backup_key,args.backup_output)):parser.error('Apply requires an approved digest and encrypted-backup paths.')
    try:
        value=apply_archive(args.data_dir,args.workspace,args.approve_digest,args.backup_key,args.backup_output,args.allow_linked_history) if args.apply else plan(args.data_dir,args.workspace)
    except (OSError,ValueError,sqlite3.Error,InvalidToken,TypeError,RecursionError):
        parser.exit(1,'Retirement failed. Review scope, stopped workers, unchanged plan, audit integrity and backup inputs. Database contents and keys were not printed.\n')
    print(json.dumps(value,sort_keys=True))


if __name__=='__main__':main()
