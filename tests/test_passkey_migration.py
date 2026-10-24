import sqlite3
import secrets
import json
import struct

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend import passkey_credentials as credentials, passkey_migration
from backend.backups import BackupError, create_backup, init_key, restore_backup, validate_database, MAGIC
from backend.passkey_ceremonies import Ceremonies, Scope
from backend.passkey_protocol import PasskeyError
from backend.store import Store, now, SCHEMA_VERSION
from test_passkey_protocol import authenticator

USER='a'*24


def legacy_store(tmp_path):
    directory=tmp_path/'source';directory.mkdir()
    store=Store(directory/'sentinelops.db')
    (directory/'.encryption-key').write_bytes(Fernet.generate_key())
    with store.connect(write=True) as c:
        c.execute('DROP TABLE passkey_ceremonies')
        c.execute('DROP TABLE passkey_credentials')
        c.execute('DELETE FROM schema_migrations WHERE version>=9')
        c.execute('DROP TABLE client_vaults')
        c.execute('DROP TABLE clients')
        c.execute('DROP TABLE workflow_steps')
        c.execute('DROP TABLE workflows');c.execute('DROP TABLE access_grants');c.execute('DROP TABLE credential_exposures');c.execute('DROP TABLE handoff_records')
        c.execute('ALTER TABLE devices DROP COLUMN allow_updates')
        c.execute('ALTER TABLE devices DROP COLUMN updates_enabled')
        c.execute('INSERT INTO users(id,email,password) VALUES(?,?,?)',(USER,'fixture@example.test','unchanged-password-hash'))
        c.execute('INSERT INTO vault_spaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                  ('v'*24,USER,'Test','personal','moss',180,1,1,1,'[]',0,1,7,'encrypted-fixture-payload',now(),now()))
    return directory,store


def test_version_nine_upgrade_preserves_ciphertext_and_is_idempotent(tmp_path):
    directory,store=legacy_store(tmp_path)
    with store.connect() as c:
        before={table:[tuple(row) for row in c.execute('SELECT * FROM '+table)] for table in ('users','vault_spaces')}
    for _ in range(2):
        reopened=Store(directory/'sentinelops.db')
        with reopened.connect() as c:
            assert [row[0] for row in c.execute('SELECT version FROM schema_migrations ORDER BY version')]==list(range(1,SCHEMA_VERSION+1))
            for table,rows in before.items(): assert [tuple(row) for row in c.execute('SELECT * FROM '+table)]==rows
            passkey_migration.validate_layout(c)


def test_failed_migration_rolls_back_both_tables_and_version_marker(tmp_path,monkeypatch):
    directory,store=legacy_store(tmp_path)
    def fail(c):
        c.execute('CREATE TABLE partial_migration(id TEXT)')
        raise RuntimeError('synthetic migration failure')
    monkeypatch.setattr(passkey_migration,'install_credentials',fail)
    with pytest.raises(RuntimeError): Store(directory/'sentinelops.db')
    with store.connect() as c:
        assert c.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0]==8
        assert not c.execute("SELECT 1 FROM sqlite_master WHERE name IN ('passkey_ceremonies','partial_migration')").fetchone()
        assert c.execute('SELECT payload FROM vault_spaces').fetchone()[0]=='encrypted-fixture-payload'


def test_already_applied_schema_with_missing_table_fails_closed(tmp_path):
    store=Store(tmp_path/'broken.db')
    with store.connect(write=True) as c: c.execute('DROP TABLE passkey_credentials')
    with pytest.raises(ValueError,match='incomplete'): Store(store.path)
    with store.connect() as c:
        assert not c.execute("SELECT 1 FROM sqlite_master WHERE name='passkey_credentials'").fetchone()


def test_future_or_gapped_migration_history_is_rejected_before_schema_creation(tmp_path):
    for versions in ([1,2,10],[1,3]):
        path=tmp_path/('future-'+str(len(versions))+'.db')
        with sqlite3.connect(path) as c:
            c.execute('CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT)')
            c.executemany('INSERT INTO schema_migrations VALUES(?,?)',[(v,'fixture') for v in versions])
        with pytest.raises(ValueError,match='schema'): Store(path)
        with sqlite3.connect(path) as c:
            assert not c.execute("SELECT 1 FROM sqlite_master WHERE name='users'").fetchone()


@pytest.mark.parametrize('version',['8','not-a-version'])
def test_malformed_schema_history_is_a_controlled_failure(tmp_path,version):
    path=tmp_path/'invalid-version.db'
    with sqlite3.connect(path) as c:
        c.execute('CREATE TABLE schema_migrations(version TEXT PRIMARY KEY,applied_at TEXT)')
        c.execute('INSERT INTO schema_migrations VALUES(?,?)',(version,'fixture'))
    with pytest.raises(ValueError,match='schema'): Store(path)
    with sqlite3.connect(path) as c:
        with pytest.raises(BackupError,match='schema'): validate_database(c,Fernet.generate_key())


def test_schema_eight_backup_restores_and_migrates_only_new_destination(tmp_path):
    source,store=legacy_store(tmp_path)
    key=tmp_path/'backup.key';init_key(key)
    archive=tmp_path/'old.sentinelbackup'
    assert create_backup(source,key,archive)['schema']==8
    destination=tmp_path/'restored'
    result=restore_backup(archive,key,destination)
    assert result['source_schema']==8 and result['schema']==SCHEMA_VERSION and result['authorization_reset']
    restored=Store(destination/'sentinelops.db')
    with restored.connect() as c:
        assert c.execute('SELECT payload,revision FROM vault_spaces').fetchone()[:]==('encrypted-fixture-payload',7)
        assert c.execute('SELECT COUNT(*) FROM passkey_ceremonies').fetchone()[0]==0
        assert c.execute('SELECT COUNT(*) FROM passkey_credentials').fetchone()[0]==0
    with store.connect() as c:
        assert c.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0]==8
        assert not c.execute("SELECT 1 FROM sqlite_master WHERE name='passkey_credentials'").fetchone()


def test_restore_revokes_saved_passkeys_and_pending_ceremonies_without_changing_source(tmp_path,authenticator):
    source,store=legacy_store(tmp_path)
    store=Store(store.path)
    party,raw_id,_,response=authenticator
    challenge=secrets.token_bytes(32)
    verified=party.register(response('create',challenge),challenge)
    with store.connect(write=True) as c: identifier=credentials.register(c,USER,party,'Test device',verified)
    service=Ceremonies(store)
    pending=service.begin(secrets.token_urlsafe(32),Scope('authentication',party,USER))
    key=tmp_path/'backup.key';init_key(key);archive=tmp_path/'new.sentinelbackup'
    assert create_backup(source,key,archive)['schema']==SCHEMA_VERSION
    destination=tmp_path/'restored'
    assert restore_backup(archive,key,destination)['source_schema']==SCHEMA_VERSION
    recovered=Store(destination/'sentinelops.db')
    with recovered.connect() as c:
        assert c.execute('SELECT COUNT(*) FROM passkey_ceremonies').fetchone()[0]==0
        assert credentials.active_ids(c,USER,party)==[]
        row=c.execute('SELECT revoked_at,revision,public_key FROM passkey_credentials WHERE id=?',(identifier,)).fetchone()
        assert row[0] is not None and row[1]==1 and row[2]==verified.credential_public_key
        assert any(event['action']=='auth.passkey_revoked' for event in Store.audit(c,'personal:'+USER)['events'])
        with pytest.raises(PasskeyError): credentials.lookup(c,USER,party,raw_id)
    with store.connect() as c:
        assert credentials.lookup(c,USER,party,raw_id).revision==0
        assert c.execute('SELECT COUNT(*) FROM passkey_ceremonies').fetchone()[0]==1


def test_revoked_key_stays_revoked_when_restored(tmp_path,authenticator):
    source,store=legacy_store(tmp_path);store=Store(store.path)
    party,_,_,response=authenticator;challenge=secrets.token_bytes(32)
    with store.connect(write=True) as c:
        identifier=credentials.register(c,USER,party,'Test',party.register(response('create',challenge),challenge))
        credentials.revoke(c,USER,party,identifier,clock=lambda:1000)
    key=tmp_path/'backup.key';init_key(key);archive=tmp_path/'revoked.sentinelbackup'
    create_backup(source,key,archive);destination=tmp_path/'restored';restore_backup(archive,key,destination)
    with sqlite3.connect(destination/'sentinelops.db') as c:
        assert c.execute('SELECT revoked_at,revision FROM passkey_credentials').fetchone()==(1000.0,1)


def test_backup_rejects_schema_nine_with_missing_credential_table(tmp_path):
    source,store=legacy_store(tmp_path);store=Store(store.path)
    with store.connect(write=True) as c: c.execute('DROP TABLE passkey_credentials')
    key=tmp_path/'backup.key';init_key(key);archive=tmp_path/'bad.sentinelbackup'
    with pytest.raises(BackupError,match='Passkey schema'): create_backup(source,key,archive)
    assert not archive.exists()


def test_partial_credential_uniqueness_cannot_replace_the_global_constraint(tmp_path):
    store=Store(tmp_path/'bad-unique.db')
    with store.connect(write=True) as c:
        ddl=c.execute("SELECT sql FROM sqlite_master WHERE name='passkey_credentials'").fetchone()[0]
        c.execute('DROP TABLE passkey_credentials')
        c.execute(ddl.replace('credential_id BLOB NOT NULL UNIQUE','credential_id BLOB NOT NULL'))
        c.execute('CREATE UNIQUE INDEX partial_fixture ON passkey_credentials(credential_id) WHERE revoked_at IS NULL')
    with pytest.raises(ValueError,match='uniqueness'): Store(store.path)


def test_authenticated_archive_with_inconsistent_schema_manifest_is_not_published(tmp_path):
    source,store=legacy_store(tmp_path);store=Store(store.path)
    key=tmp_path/'backup.key';init_key(key);archive=tmp_path/'mismatch.sentinelbackup'
    create_backup(source,key,archive)
    encrypted=archive.read_bytes();cipher=AESGCM(key.read_bytes())
    payload=cipher.decrypt(encrypted[8:20],encrypted[20:],MAGIC)
    length=struct.unpack('>I',payload[:4])[0]
    manifest=json.loads(payload[4:4+length]);manifest['schema']=8
    modified=json.dumps(manifest).encode()
    nonce=secrets.token_bytes(12)
    archive.write_bytes(MAGIC+nonce+cipher.encrypt(nonce,struct.pack('>I',len(modified))+modified+payload[4+length:],MAGIC))
    destination=tmp_path/'not-published'
    with pytest.raises(BackupError,match='schema differ'): restore_backup(archive,key,destination)
    assert not destination.exists()
    assert not list(tmp_path.glob('.sentinel-restore-*'))
