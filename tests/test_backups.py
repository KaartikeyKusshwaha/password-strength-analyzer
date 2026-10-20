import sqlite3

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from backend.app import Settings, create_app
from backend.backups import BackupError, create_backup, init_key, main, restore_backup, SCHEMA
from backend.security import verify_password
from backend.store import Store, now
from test_platform import system, PASSWORD, post


def prepare(system, tmp_path):
    app, client, source = system
    key = tmp_path / 'backup.key'
    archive = tmp_path / 'backup.sentinelbackup'
    init_key(key)
    return source, key, archive


def test_live_wal_restore_preserves_envelopes_and_mfa_but_revokes_work(system, tmp_path):
    source, key, archive = prepare(system, tmp_path)
    store = Store(source / 'sentinelops.db')
    cipher = Fernet((source / '.encryption-key').read_bytes())
    # Keep a live reader so committed pages can remain in the WAL.
    reader = sqlite3.connect(source / 'sentinelops.db')
    reader.execute('BEGIN')
    reader.execute('SELECT * FROM users').fetchall()
    with store.connect(write=True) as c:
        user = c.execute('SELECT id FROM users').fetchone()[0]
        workspace = c.execute('SELECT id FROM workspaces').fetchone()[0]
        c.execute('UPDATE users SET mfa=?,mfa_draft=? WHERE id=?',
                  (cipher.encrypt(b'FIXTURE-MFA-SECRET').decode(), cipher.encrypt(b'fixture draft').decode(), user))
        c.execute("INSERT INTO vault_spaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  ('restore-fixture', user, 'Private', 'personal', 'moss', 180, 1, 1, 1, '[]', 0, 0, 7, '{"ciphertext":"fixture-only"}', now(), now()))
        c.execute('INSERT INTO sharing_identities VALUES(?,?,?,?,?)', (user, 'public', 'fingerprint', 'encrypted-identity', now()))
        c.execute('INSERT INTO team_vaults(id,workspace,owner,name,manifest,payload,epoch,revision,rotation_required,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',
                  ('shared-fixture', workspace, user, 'Shared', 'manifest-ciphertext', 'shared-ciphertext', 2, 9, 0, now()))
        c.execute('INSERT INTO team_grants VALUES(?,?,?,?,?,?)', ('shared-fixture', user, 'owner', 'wrapped-key-ciphertext', 1, now()))
        c.execute('INSERT INTO credential_actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                  ('action-fixture', user, 'restore-fixture', 'personal', workspace, 'encrypted-manifest', 1, 'running', '{}', 'old-lease-hash', 'old-token', 9999999999, now(), 9999999999))
        c.execute('INSERT INTO companions(token,user,label,expires) VALUES(?,?,?,?)', ('old-token', user, 'fixture', 9999999999))
        c.execute('INSERT INTO devices(id,token,workspace,user,label,targets,expires) VALUES(?,?,?,?,?,?,?)', ('old-device', 'old-device-token', workspace, user, 'fixture', '[]', 9999999999))
        Store.put(c, workspace, 'watches', dict(id='watch', enabled=True, revision=3, active_run='run', next_due=1))
        for kind in ('operations', 'jobs', 'watch_runs'):
            Store.put(c, workspace, kind, dict(id=kind, status='queued', lease='old-lease', lease_expires=9999999999))
        Store.event(c, workspace, user, 'fixture.created', 'restore-fixture')
        Store.put(c,workspace,'ownership_transfers',{'id':'pending-handoff','status':'pending','document':{'vault_id':'shared-fixture'}})
    try:
        create_backup(source, key, archive)
    finally:
        reader.close()
    assert b'FIXTURE-MFA-SECRET' not in archive.read_bytes()
    assert b'ciphertext' not in archive.read_bytes()
    destination = tmp_path / 'recovered'
    restore_backup(archive, key, destination)
    recovered = Store(destination / 'sentinelops.db')
    with recovered.connect() as c:
        account = c.execute('SELECT * FROM users').fetchone()
        assert verify_password(PASSWORD, account['password'])
        assert cipher.decrypt(account['mfa'].encode()) == b'FIXTURE-MFA-SECRET'
        assert account['mfa_draft'] is None
        assert c.execute("SELECT payload,revision FROM vault_spaces WHERE id='restore-fixture'").fetchone()[:] == ('{"ciphertext":"fixture-only"}', 7)
        assert c.execute('SELECT encrypted FROM sharing_identities').fetchone()[0] == 'encrypted-identity'
        assert c.execute('SELECT payload,epoch,revision FROM team_vaults').fetchone()[:] == ('shared-ciphertext', 2, 9)
        assert c.execute('SELECT envelope,accepted FROM team_grants').fetchone()[:] == ('wrapped-key-ciphertext', 1)
        assert c.execute('SELECT status,lease_hash,lease_connection,lease_expires FROM credential_actions').fetchone()[:] == ('cancelled', None, None, None)
        for table in ('sessions', 'invites', 'devices', 'companions'):
            assert c.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] == 0
        for kind in ('operations', 'jobs', 'watch_runs'):
            job = Store.all(c, workspace, kind)[0]
            assert job['status'] == 'interrupted' and 'lease' not in job
        watch = Store.all(c, workspace, 'watches')[0]
        assert not watch['enabled'] and watch['active_run'] is None and watch['next_due'] is None
        assert watch['revision'] == 4
        audit = Store.audit(c, workspace)
        assert audit['valid'] and any(event['action']=='backup.restored' for event in audit['events'])
        assert audit['events'][-1]['action']=='team_vault.recovery_restored'
        personal=Store.audit(c,'personal:'+user)
        assert personal['valid'] and personal['events'][-1]['action']=='vault.recovery_restored'
        assert Store.get(c,workspace,'ownership_transfers','pending-handoff')['status']=='cancelled'
    # Starting a recovered app must not create a fresh owner or drop encrypted data.
    with TestClient(create_app(Settings(data_dir=destination, groq_key=''))) as client:
        assert client.get('/api/me').status_code == 401
        assert not (destination / '.bootstrap-token').exists()
    with store.connect() as c:
        assert c.execute('SELECT COUNT(*) FROM sessions').fetchone()[0] > 0
        assert Store.all(c, workspace, 'watches')[0]['enabled']


@pytest.mark.parametrize('damage', ['wrong-key', 'tamper', 'truncated', 'header'])
def test_bad_archive_never_publishes_destination(system, tmp_path, damage):
    source, key, archive = prepare(system, tmp_path)
    create_backup(source, key, archive)
    if damage == 'wrong-key':
        key = tmp_path / 'wrong.key'
        init_key(key)
    else:
        value = bytearray(archive.read_bytes())
        if damage == 'tamper':
            value[-1] ^= 1
        elif damage == 'header':
            value[0] ^= 1
        else:
            value = value[:24]
        archive.write_bytes(value)
    destination = tmp_path / 'refused'
    with pytest.raises(BackupError):
        restore_backup(archive, key, destination)
    assert not destination.exists()
    assert not list(tmp_path.glob('.sentinel-restore-*'))


def test_never_overwrites_files_or_existing_directories(system, tmp_path):
    source, key, archive = prepare(system, tmp_path)
    original_key = key.read_bytes()
    with pytest.raises(FileExistsError):
        init_key(key)
    assert key.read_bytes() == original_key
    create_backup(source, key, archive)
    original_archive = archive.read_bytes()
    with pytest.raises(FileExistsError):
        create_backup(source, key, archive)
    assert archive.read_bytes() == original_archive
    for destination in (source, tmp_path / 'empty-but-existing'):
        destination.mkdir(exist_ok=True)
        with pytest.raises(BackupError):
            restore_backup(archive, key, destination)
    with pytest.raises(BackupError):
        create_backup(source, key, key)


def test_missing_or_mismatched_server_key_fails_before_backup(system, tmp_path):
    source, key, archive = prepare(system, tmp_path)
    store = Store(source / 'sentinelops.db')
    server_key = source / '.encryption-key'
    cipher = Fernet(server_key.read_bytes())
    with store.connect(write=True) as c:
        c.execute('UPDATE users SET mfa=?', (cipher.encrypt(b'fixture secret').decode(),))
    server_key.write_bytes(Fernet.generate_key())
    from cryptography.fernet import InvalidToken
    with pytest.raises(InvalidToken):
        create_backup(source, key, archive)
    assert not archive.exists()
    server_key.unlink()
    with pytest.raises(BackupError):
        create_backup(source, key, archive)


def test_invalid_audit_or_future_schema_cannot_be_backed_up(system, tmp_path):
    source, key, archive = prepare(system, tmp_path)
    store = Store(source / 'sentinelops.db')
    with store.connect(write=True) as c:
        c.execute("UPDATE audit SET target='tampered'")
    with pytest.raises(BackupError, match='Audit'):
        create_backup(source, key, archive)
    assert not archive.exists()
    with store.connect(write=True) as c:
        c.execute('INSERT INTO schema_migrations VALUES(?,?)', (SCHEMA+1,now()))
    with pytest.raises(BackupError, match='schema'):
        create_backup(source, key, archive)


def test_cli_logs_no_key_material(system, tmp_path, capsys):
    source, key, archive = prepare(system, tmp_path)
    main(['create', '--data-dir', str(source), '--key-file', str(key), '--output', str(archive)])
    output = capsys.readouterr()
    assert output.err == '' and output.out.startswith('Completed.')
    with pytest.raises(SystemExit) as error:
        main(['restore', '--input', str(archive), '--key-file', str(key), '--destination', str(source)])
    assert error.value.code == 1
    assert 'No live data was overwritten' in capsys.readouterr().err


def test_recovered_owner_can_sign_in_with_existing_password(system, tmp_path):
    source, key, archive = prepare(system, tmp_path)
    create_backup(source, key, archive)
    destination = tmp_path / 'sign-in-drill'
    restore_backup(archive, key, destination)
    with TestClient(create_app(Settings(data_dir=destination, groq_key=''))) as client:
        # A restore is not an account reset or a new bootstrap installation.
        assert client.get('/api/me').status_code == 401
        response = post(client, '/login', {'email': 'owner@example.test', 'password': PASSWORD})
        assert response.status_code == 200
        assert client.get('/api/me').json()['email'] == 'owner@example.test'


def test_bad_key_size_and_database_size_are_rejected(system, tmp_path, monkeypatch):
    source, key, archive = prepare(system, tmp_path)
    key.write_bytes(b'not-a-backup-key')
    with pytest.raises(BackupError, match='32-byte'):
        create_backup(source, key, archive)
    key.unlink()
    init_key(key)
    monkeypatch.setattr('backend.backups.MAX_BYTES', 100)
    with pytest.raises(BackupError, match='size'):
        create_backup(source, key, archive)
    assert not archive.exists()


def test_personal_audit_corruption_is_also_rejected(system, tmp_path):
    source,key,archive=prepare(system,tmp_path)
    store=Store(source/'sentinelops.db')
    with store.connect(write=True) as c:
        user=c.execute('SELECT id FROM users').fetchone()[0]
        Store.event(c,'personal:'+user,user,'vault.saved','fixture-vault')
        c.execute("UPDATE audit SET target='altered' WHERE workspace=?",('personal:'+user,))
    with pytest.raises(BackupError,match='Audit'):
        create_backup(source,key,archive)
    assert not archive.exists()
