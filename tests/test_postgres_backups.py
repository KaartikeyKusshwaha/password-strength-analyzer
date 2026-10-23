import pytest
from cryptography.fernet import Fernet,InvalidToken
from backend.backups import BackupError,create_backup,init_key,read_backup,restore_backup
from backend.postgres_backups import export_backup,import_backup
from backend.store import Store,now
from test_platform import system
from test_postgres_schema import postgres_schema
from test_postgres_store import store_for


@pytest.fixture
def archive(system,tmp_path):
    app,_,directory=system
    server_key=(directory/'.encryption-key').read_bytes()
    with app.state.store.connect(write=True) as c:
        user=c.execute('SELECT id FROM users').fetchone()[0]
        workspace=c.execute('SELECT id FROM workspaces').fetchone()[0]
        c.execute('UPDATE users SET mfa=? WHERE id=?',(Fernet(server_key).encrypt(b'fixture-mfa').decode(),user))
        c.execute('INSERT INTO vault_spaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',('test-vault',user,'Private','personal','moss',180,1,1,1,'[]',0,0,7,'{"ciphertext":"fixture-ciphertext"}',now(),now()))
        c.execute('INSERT INTO team_vaults(id,workspace,owner,name,manifest,payload,epoch,revision,rotation_required,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',('shared',workspace,user,'Shared','encrypted-manifest','encrypted-shared-payload',4,9,0,now()))
        c.execute('INSERT INTO team_grants VALUES(?,?,?,?,?,?)',('shared',user,'owner','encrypted-envelope',1,now()))
        c.execute('INSERT INTO passkey_credentials VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',('key',user,'https://example.test','example.test',b'\x00\xffcredential',b'\x00\x80public-key',5,'single_device',0,'Test',1.0,None,None,0))
        Store.put(c,workspace,'fixture',{'id':'z-first','value':'ciphertext-z'})
        Store.put(c,workspace,'fixture',{'id':'a-second','value':'ciphertext-a'})
        Store.event(c,workspace,user,'fixture.before_export','shared')
    key=tmp_path/'archive.key';init_key(key)
    path=tmp_path/'source.sentinelbackup';create_backup(directory,key,path)
    return path,key,server_key,workspace


def test_sqlite_to_postgres_encrypted_export_and_isolated_restore(archive,postgres_schema,tmp_path):
    path,key,server_key,workspace=archive
    store=store_for(postgres_schema[3])
    result=import_backup(store,path,key,server_key)
    assert result['authorization_reset'] and result['rows']>15
    with store.connect() as c:
        assert c.execute('SELECT payload,revision FROM vault_spaces').fetchone()[:]==('{"ciphertext":"fixture-ciphertext"}',7)
        assert c.execute('SELECT payload,epoch,revision FROM team_vaults').fetchone()[:]==('encrypted-shared-payload',4,9)
        assert c.execute('SELECT envelope FROM team_grants').fetchone()[0]=='encrypted-envelope'
        assert c.execute('SELECT credential_id,public_key,revoked_at FROM passkey_credentials').fetchone()[:2]==(b'\x00\xffcredential',b'\x00\x80public-key')
        assert c.execute('SELECT revoked_at FROM passkey_credentials').fetchone()[0] is not None
        assert c.execute('SELECT count(*) FROM sessions').fetchone()[0]==0
        assert [v['id'] for v in Store.all(c,workspace,'fixture')]==['a-second','z-first']
        before=Store.audit(c,workspace);assert before['valid']
    with store.connect(write=True) as c:Store.event(c,workspace,'test','fixture.after_import','shared')
    with store.connect() as c:
        after=Store.audit(c,workspace)
        assert after['valid'] and len(after['events'])==len(before['events'])+1
    output=tmp_path/'postgres.sentinelbackup'
    export_backup(store,server_key,key,output)
    assert b'fixture-ciphertext' not in output.read_bytes()
    read_backup(output,key)
    destination=tmp_path/'isolated-restore';restore_backup(output,key,destination)
    recovered=Store(destination/'sentinelops.db')
    with recovered.connect() as c:
        assert c.execute('SELECT payload,revision FROM vault_spaces').fetchone()[:]==('{"ciphertext":"fixture-ciphertext"}',7)
        assert Store.audit(c,workspace)['valid']
        assert c.execute('SELECT credential_id FROM passkey_credentials').fetchone()[0]==b'\x00\xffcredential'
    from deploy.postgres_schema import prepare
    connection,_,pg,schema=postgres_schema
    copy_schema=schema+'_restore'
    try:
        connection.execute(prepare(copy_schema)[0],prepare=False)
        restored_store=store_for(copy_schema)
        import_backup(restored_store,output,key,server_key)
        with restored_store.connect() as c:
            assert c.execute('SELECT payload,revision FROM vault_spaces').fetchone()[:]==('{"ciphertext":"fixture-ciphertext"}',7)
            assert Store.audit(c,workspace)['valid']
    finally:
        connection.execute(pg.sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(pg.sql.Identifier(copy_schema)))
    with pytest.raises(FileExistsError):export_backup(store,server_key,key,output)


def test_import_refuses_nonempty_target_and_wrong_key_without_changes(archive,postgres_schema):
    path,key,server_key,_=archive;store=store_for(postgres_schema[3])
    with pytest.raises(BackupError,match='does not match'):import_backup(store,path,key,Fernet.generate_key())
    with store.connect(write=True) as c:c.execute('INSERT INTO workspaces VALUES(?,?,?)',('retain','Retain',0))
    with pytest.raises(BackupError,match='empty target'):import_backup(store,path,key,server_key)
    with store.connect() as c:
        assert c.execute('SELECT id FROM workspaces').fetchone()[0]=='retain'
        assert c.execute('SELECT count(*) FROM users').fetchone()[0]==0


def test_failure_mid_import_rolls_back_all_tables(archive,postgres_schema,monkeypatch):
    path,key,server_key,_=archive;store=store_for(postgres_schema[3])
    import backend.postgres_backups as module
    original=module.digest_rows;calls=0
    def fail_late(*args,**kwargs):
        nonlocal calls
        calls+=1
        if calls==18:raise RuntimeError('simulated mid-import failure')
        return original(*args,**kwargs)
    monkeypatch.setattr(module,'digest_rows',fail_late)
    with pytest.raises(RuntimeError,match='mid-import'):import_backup(store,path,key,server_key)
    with store.connect() as c:
        for table in module.layout():
            if table!='schema_migrations':assert c.execute('SELECT count(*) FROM '+module.quote(table)).fetchone()[0]==0
        assert c.execute('SELECT count(*) FROM schema_migrations').fetchone()[0]==15


def test_export_rejects_wrong_mfa_key_and_never_writes_archive(archive,postgres_schema,tmp_path):
    path,key,server_key,_=archive;store=store_for(postgres_schema[3]);import_backup(store,path,key,server_key)
    output=tmp_path/'must-not-exist.sentinelbackup'
    with pytest.raises(InvalidToken):export_backup(store,Fernet.generate_key(),key,output)
    assert not output.exists()
