"""Retire exact historical components only after a matching encrypted backup."""
import hashlib
import json
import sqlite3
from unittest.mock import patch
import pytest
from backend import mail_retirement as retirement
from backend.backups import init_key,restore_backup,BackupError
from backend.store import Store,uid,canonical
from test_platform import system,asset

PRIVATE='private-historical-marker-not-for-preview'


def history(system):
    app,client,path=system;workspace=client.get('/api/me').json()['workspace'];application=asset(client)['id']
    scan,finding,task,other=uid(),uid(),uid(),uid()
    with app.state.store.connect(write=True) as c:
        Store.put(c,workspace,'scans',{'id':scan,'kind':'email','asset_id':application,'status':'complete','finding_ids':[finding],'label':PRIVATE})
        Store.put(c,workspace,'findings',{'id':finding,'kind':'email','rule':'MAIL001','asset_id':application,'scan_id':scan,'status':'open'})
        Store.put(c,workspace,'tasks',{'id':task,'finding_id':finding,'status':'open','note':PRIVATE})
        Store.put(c,workspace,'scans',{'id':other,'kind':'python','asset_id':application,'status':'complete','finding_ids':[]})
    key=path/'retirement.backup-key';init_key(key)
    return app,path,workspace,key,path/'before-mail-retirement.sentinelbackup',scan,finding,task,other


def apply(value,digest,**kwargs):
    app,path,workspace,key,backup,*_=value
    return retirement.apply_archive(path,workspace,digest,key,backup,**kwargs)


def test_preview_is_scoped_redacted_and_does_not_pull_unrelated_asset_checks(system):
    value=history(system);app,path,workspace,key,backup,scan,finding,task,other=value
    with app.state.store.connect(write=True) as c:
        Store.put(c,'other-workspace','findings',{'id':uid(),'kind':'email','rule':'MAIL002','scan_id':scan})
    preview=retirement.plan(path,workspace)
    assert {row['id'] for row in preview['records']}=={scan,finding,task}
    assert preview['linked_history']=={'tasks':1} and not preview['active_records']
    assert PRIVATE not in json.dumps(preview) and not backup.exists()
    with pytest.raises(retirement.RetirementError,match='explicit scope'):apply(value,preview['digest'])
    assert not backup.exists()


def test_archive_preserves_exact_records_and_audit_after_verified_recoverable_backup(system):
    value=history(system);app,path,workspace,key,backup,scan,finding,task,other=value
    with app.state.store.connect() as c:
        before=Store.audit(c,workspace)['events'];raw=c.execute('SELECT data FROM entities WHERE id=?',(scan,)).fetchone()[0]
    preview=retirement.plan(path,workspace)
    result=apply(value,preview['digest'],allow_linked_history=True)
    assert result['archived']==3 and result['backup_created'] and PRIVATE.encode() not in backup.read_bytes()
    with app.state.store.connect() as c:
        assert Store.get(c,workspace,'scans',scan) is None
        saved=Store.get(c,workspace,retirement.ARCHIVE,scan)
        assert saved['source_json']==raw and saved['source_sha256']==hashlib.sha256(raw.encode()).hexdigest()
        assert saved['backup_sha256']==result['backup_sha256']
        assert Store.get(c,workspace,'scans',other) and Store.audit(c,workspace)['valid']
        assert Store.audit(c,workspace)['events'][:-1]==before
    assert not retirement.plan(path,workspace)['records']
    restored=path/'restored-before-retirement';restore_backup(backup,key,restored)
    assert retirement.plan(restored,workspace)['digest']==preview['digest']
    empty=retirement.plan(path,workspace)
    assert retirement.apply_archive(path,workspace,empty['digest'],key,path/'unused-backup')['archived']==0
    assert not (path/'unused-backup').exists()


def test_changed_scope_and_unavailable_backup_never_change_history(system):
    value=history(system);app,path,workspace,key,backup,scan,*_=value
    preview=retirement.plan(path,workspace)
    with app.state.store.connect(write=True) as c:
        record=Store.get(c,workspace,'scans',scan);record['label']='changed';Store.put(c,workspace,'scans',record)
    with pytest.raises(retirement.RetirementError,match='Plan changed'):apply(value,preview['digest'],allow_linked_history=True)
    assert not backup.exists()
    current=retirement.plan(path,workspace)
    with pytest.raises(BackupError):retirement.apply_archive(path,workspace,current['digest'],path/'missing-key',backup,True)
    with app.state.store.connect() as c:assert Store.get(c,workspace,'scans',scan)


def test_backup_race_and_audit_failure_roll_back_the_archive(system):
    value=history(system);app,path,workspace,key,backup,scan,*_=value
    preview=retirement.plan(path,workspace);real=retirement.create_backup
    def race(*args):
        result=real(*args)
        with app.state.store.connect(write=True) as c:
            record=Store.get(c,workspace,'scans',scan);record['label']='concurrent update';Store.put(c,workspace,'scans',record)
        return result
    with patch.object(retirement,'create_backup',side_effect=race):
        with pytest.raises(retirement.RetirementError,match='History changed'):apply(value,preview['digest'],allow_linked_history=True)
    current=retirement.plan(path,workspace)
    with patch.object(Store,'event',side_effect=sqlite3.OperationalError('fixture audit failure')):
        with pytest.raises(sqlite3.OperationalError):retirement.apply_archive(path,workspace,current['digest'],key,path/'second-backup',True)
    with app.state.store.connect() as c:
        assert Store.get(c,workspace,'scans',scan) and not Store.all(c,workspace,retirement.ARCHIVE)


@pytest.mark.parametrize('blocked',['active','unknown'])
def test_active_workers_and_unknown_references_fail_closed(system,blocked):
    value=history(system);app,path,workspace,key,backup,scan,finding,*_=value
    with app.state.store.connect(write=True) as c:
        Store.put(c,workspace,'operations' if blocked=='active' else 'unknown_history',{'id':uid(),('scan_id' if blocked=='active' else 'unrecognized_reference'):scan,'status':'running'})
    preview=retirement.plan(path,workspace)
    assert preview['active_records'] if blocked=='active' else preview['unsupported_records']
    with pytest.raises(retirement.RetirementError):apply(value,preview['digest'],allow_linked_history=True)
    assert not backup.exists()


def test_cli_preview_and_failure_never_print_historical_contents(system,capsys):
    value=history(system);app,path,workspace,key,backup,*_=value
    retirement.main(['--data-dir',str(path),'--workspace',workspace])
    output=capsys.readouterr()
    assert PRIVATE not in output.out and json.loads(output.out)['records']
    with pytest.raises(SystemExit) as stopped:
        retirement.main(['--data-dir',str(path),'--workspace',workspace,'--apply','--approve-digest','0'*64,'--backup-key',str(key),'--backup-output',str(backup),'--allow-linked-history'])
    assert stopped.value.code==1
    assert PRIVATE not in capsys.readouterr().err and not backup.exists()


def test_preview_refuses_unbounded_entity_sets_before_loading_history(system):
    app,client,path=system;workspace=client.get('/api/me').json()['workspace']
    with app.state.store.connect(write=True) as c:
        c.executemany('INSERT INTO entities VALUES(?,?,?,?)',[(uid(),workspace,'unrelated_history','{}') for _ in range(10001)])
    with pytest.raises(retirement.RetirementError,match='bounded'):retirement.plan(path,workspace)


def test_replacing_verified_backup_before_commit_preserves_active_history(system):
    value=history(system);app,path,workspace,key,backup,scan,*_=value
    preview=retirement.plan(path,workspace);read=retirement.read_backup
    def replace(*args):
        result=read(*args);encrypted=backup.read_bytes()
        backup.write_bytes(encrypted[:-1]+bytes([encrypted[-1]^1]))
        return result
    with patch.object(retirement,'read_backup',side_effect=replace):
        with pytest.raises(retirement.RetirementError,match='Verified backup changed'):apply(value,preview['digest'],allow_linked_history=True)
    with app.state.store.connect() as c:assert Store.get(c,workspace,'scans',scan) and not Store.all(c,workspace,retirement.ARCHIVE)


def test_mixed_review_history_requires_explicit_linked_scope_and_preserves_its_asset(system):
    value=history(system);app,path,workspace,key,backup,scan,finding,task,other=value;review=uid()
    with app.state.store.connect(write=True) as c:
        Store.put(c,workspace,'security_reviews',{'id':review,'status':'complete','checks':[{'action':'email','scan_id':scan},{'action':'python','scan_id':other}]})
        application=Store.get(c,workspace,'scans',other)['asset_id']
    preview=retirement.plan(path,workspace)
    assert {record['id'] for record in preview['records']}=={scan,finding,task,other,review}
    assert preview['linked_history']['scans']==1
    with pytest.raises(retirement.RetirementError,match='explicit scope'):apply(value,preview['digest'])
    with app.state.store.connect() as c:assert Store.get(c,workspace,'scans',other)
    assert apply(value,preview['digest'],allow_linked_history=True)['archived']==5
    with app.state.store.connect() as c:
        assert Store.get(c,workspace,retirement.ARCHIVE,other)
        assert Store.get(c,workspace,'assets',application)
