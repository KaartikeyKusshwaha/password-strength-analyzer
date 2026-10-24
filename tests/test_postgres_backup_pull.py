import json
from pathlib import Path

import pytest
from backend.backups import BackupError,restore_backup
from backend.store import Store
from deploy.postgres_backup_pull import configuration,pull,main
from test_platform import system
from test_postgres_backups import archive
from test_postgres_schema import postgres_schema
from test_postgres_store import store_for
from backend.postgres_backups import import_backup


def config(tmp_path,key,server_key):
    destination=tmp_path/'retained';destination.mkdir()
    private=tmp_path/'private';private.mkdir()
    (private/'url').write_text('postgresql://fixture.invalid/db?sslmode=verify-full')
    (private/'mfa-key').write_bytes(server_key)
    value={'database_url_file':str(private/'url'),'server_key_file':str(private/'mfa-key'),'backup_key_file':str(key),'destination':str(destination)}
    path=private/'configuration.json';path.write_text(json.dumps(value))
    return path,value,configuration(path)


def test_verified_postgres_pull_publishes_archive_and_receipt_then_restores(archive,postgres_schema,tmp_path):
    source,key,server_key,workspace=archive;store=store_for(postgres_schema[3]);import_backup(store,source,key,server_key)
    _,_,cfg=config(tmp_path,key,server_key)
    result=pull(cfg,store_factory=lambda _:store)
    assert json.loads((cfg['destination']/(result['archive']+'.receipt.json')).read_text())==result
    output=cfg['destination']/result['archive']
    assert b'fixture-ciphertext' not in output.read_bytes() and 'fixture.invalid' not in json.dumps(result)
    assert not list(cfg['destination'].glob('.sentinel-pg-pull-*'))
    restored=tmp_path/'restore';restore_backup(output,key,restored)
    with Store(restored/'sentinelops.db').connect() as c:
        assert Store.audit(c,workspace)['valid']
        assert c.execute('SELECT payload,revision FROM vault_spaces').fetchone()[:]==('{"ciphertext":"fixture-ciphertext"}',7)


@pytest.mark.parametrize('failure',['connection','export'])
def test_failed_pull_never_publishes_success_or_exposes_credentials(archive,tmp_path,monkeypatch,capsys,failure):
    _,key,server_key,_=archive;path,_,cfg=config(tmp_path,key,server_key)
    import deploy.postgres_backup_pull as module
    def failed(*args,**kwargs):raise ValueError('secret credential fixture-only')
    if failure=='export':
        monkeypatch.setattr(module,'export_backup',failed)
        factory=lambda _:object()
    else:factory=failed
    with pytest.raises(ValueError):pull(cfg,store_factory=factory)
    assert list(cfg['destination'].iterdir())==[]
    monkeypatch.setattr(module,'pull',failed)
    with pytest.raises(SystemExit) as result:main(['--config',str(path)])
    assert result.value.code==1
    output=capsys.readouterr()
    assert 'secret credential' not in output.err and not output.out


@pytest.mark.parametrize('change',['same_file','secret_inside_destination','unknown_field','relative_path'])
def test_configuration_rejects_unsafe_storage(archive,tmp_path,change):
    _,key,server_key,_=archive;path,value,cfg=config(tmp_path,key,server_key)
    if change=='same_file':value['server_key_file']=value['backup_key_file']
    elif change=='secret_inside_destination':
        inside=cfg['destination']/'secret';inside.write_bytes(b'fixture');value['database_url_file']=str(inside)
    elif change=='unknown_field':value['password']='not accepted'
    else:value['database_url_file']='relative-url-file'
    path.write_text(json.dumps(value))
    with pytest.raises(BackupError):configuration(path)
