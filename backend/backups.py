"""Offline operator backups. Never exposes a database-download web endpoint."""
import argparse
import json
import os
from pathlib import Path
import secrets
import sqlite3
import struct
import tempfile
import time

from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.store import Store, canonical, now, SCHEMA_VERSION
from backend.passkey_migration import validate_layout

MAGIC = b'SNTLBK01'
MAX_BYTES = 128 * 1024 * 1024
SCHEMA = SCHEMA_VERSION
SUPPORTED_SCHEMAS = (8, 9, 10, SCHEMA)


class BackupError(ValueError):
    """Public errors deliberately exclude source records and key material."""


def private_write(path, content):
    # Exclusive creation: no overwrites, including dangling symlinks.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise


def read_bounded(path, maximum):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise BackupError('A regular, non-symlink input file is required.')
    with path.open('rb') as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise BackupError('Input exceeds the supported backup size.')
    return value


def load_key(path):
    value = read_bounded(path, 32)
    if len(value) != 32:
        raise BackupError('Backup key must be the generated 32-byte key file.')
    return value


def init_key(path):
    private_write(Path(path), AESGCM.generate_key(bit_length=256))


def validate_database(connection, server_key):
    if connection.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
        raise BackupError('Database integrity check failed.')
    versions = [r[0] for r in connection.execute('SELECT version FROM schema_migrations ORDER BY version')]
    if not versions or not all(type(v) is int for v in versions) or versions[-1] not in SUPPORTED_SCHEMAS or versions != list(range(1, versions[-1] + 1)):
        raise BackupError('Unsupported database schema; use the matching application release.')
    schema = versions[-1]
    if schema >= 9:
        try: validate_layout(connection)
        except ValueError: raise BackupError('Passkey schema validation failed.') from None
    if schema >= 10:
        from .device_update_migration import validate_layout as validate_device_updates
        try: validate_device_updates(connection)
        except ValueError: raise BackupError("Device update schema validation failed.") from None
    if schema >= 11:
        from .access_migration import validate_layout as validate_client_access
        try: validate_client_access(connection)
        except ValueError: raise BackupError('Client access schema validation failed.') from None
    cipher = Fernet(server_key)
    # Detect a missing/mismatched server key before declaring recovery possible.
    for row in connection.execute('SELECT mfa,mfa_draft FROM users'):
        for encrypted in row:
            if encrypted:
                cipher.decrypt(encrypted.encode())
    connection.row_factory = sqlite3.Row
    for row in connection.execute('SELECT DISTINCT workspace FROM audit').fetchall():
        if not isinstance(row['workspace'],str) or not row['workspace']:
            raise BackupError('Audit scope validation failed.')
        if not Store.audit(connection, row['workspace'])['valid']:
            raise BackupError('Audit chain validation failed.')
    connection.row_factory = None
    return schema


def create_backup(data_dir, key_file, output):
    data_dir = Path(data_dir).resolve(strict=True)
    database = data_dir / 'sentinelops.db'
    if database.is_symlink() or not database.is_file():
        raise BackupError('Source database is missing or linked.')
    server_key = read_bounded(data_dir / '.encryption-key', 44)
    backup_key = load_key(key_file)
    if Path(output).resolve() == Path(key_file).resolve():
        raise BackupError('The backup and its key must be separate files.')
    started = time.monotonic()

    def progress(status, remaining, total):
        if time.monotonic() - started > 30 or total * page_size > MAX_BYTES:
            raise BackupError('Snapshot exceeded its time or size budget.')

    # Online backup includes committed WAL pages; no plaintext snapshot on disk.
    source = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)
    snapshot = sqlite3.connect(':memory:')
    try:
        page_size = source.execute('PRAGMA page_size').fetchone()[0]
        if source.execute('PRAGMA page_count').fetchone()[0] * page_size > MAX_BYTES:
            raise BackupError('Database exceeds the supported backup size.')
        source.backup(snapshot, pages=256, progress=progress, sleep=0.05)
        source_schema = validate_database(snapshot, server_key)
        database_bytes = snapshot.serialize()
    finally:
        snapshot.close()
        source.close()
    manifest = canonical({'format': 1, 'schema': source_schema, 'created_at': now(),
                          'database_bytes': len(database_bytes)}).encode()
    payload = struct.pack('>I', len(manifest)) + manifest + server_key + database_bytes
    if len(payload) > MAX_BYTES:
        raise BackupError('Database exceeds the supported backup size.')
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(backup_key).encrypt(nonce, payload, MAGIC)
    private_write(Path(output), MAGIC + nonce + encrypted)
    return {'created_at': json.loads(manifest)['created_at'], 'schema': source_schema}


def suspend_authorizations(connection):
    """Do not replay pre-disaster bearer grants, approvals or scheduled work."""
    for table in ('sessions', 'invites', 'companions', 'devices'):
        connection.execute(f'DELETE FROM {table}')
    connection.execute("DELETE FROM entities WHERE workspace='system:extension-connect' AND kind='extension_connect'")
    connection.execute("DELETE FROM entities WHERE workspace='system:extension-security' AND kind='security_connection'")
    connection.execute("DELETE FROM entities WHERE workspace='system:device-pairing' AND kind='device_pairing'")
    connection.execute('DELETE FROM passkey_ceremonies')
    for row in connection.execute('SELECT id,user FROM passkey_credentials WHERE revoked_at IS NULL').fetchall():
        Store.event(connection,'personal:'+row['user'],'system:restore','auth.passkey_revoked',row['id'])
    connection.execute('UPDATE passkey_credentials SET revoked_at=?,revision=revision+1 WHERE revoked_at IS NULL',(time.time(),))
    connection.execute('UPDATE users SET mfa_draft=NULL')
    cancelled=connection.execute("SELECT id,workspace,user,kind FROM credential_actions WHERE status NOT IN ('complete','cancelled','expired')").fetchall()
    connection.execute("UPDATE credential_actions SET status='cancelled',lease_hash=NULL,lease_connection=NULL,lease_expires=NULL WHERE status NOT IN ('complete','cancelled','expired')")
    for row in cancelled:
        Store.event(connection,row['workspace'] if row['kind']=='shared' else 'personal:'+row['user'],'system:restore','credential_action.cancelled',row['id'])
    for row in connection.execute("SELECT id,workspace,kind,data FROM entities WHERE kind IN ('jobs','operations','security_reviews','watch_runs','watches','ownership_transfers')").fetchall():
        value = json.loads(row['data'])
        if row['kind'] == 'ownership_transfers' and value.get('status')=='pending':
            value.update(status='cancelled',reason='backup_restored',finished_at=now())
            Store.event(connection,row['workspace'],'system:restore','team_vault.ownership_cancelled',value['document']['vault_id']+':'+value['id'])
        elif row['kind'] == 'watches':
            value.update(enabled=False, next_due=None, active_run=None,
                         revision=value['revision'] + 1, last_status='paused')
        elif value.get('status') in ('queued', 'running'):
            value.update(status='interrupted', error='Backup restored; start a new check explicitly.', finished_at=now())
            if row['kind']=='security_reviews':
                for step in value['checks']:
                    if step['status'] in {'pending','running'}:step['status']='interrupted'
            value.pop('lease', None)
            value.pop('lease_expires', None)
        connection.execute('UPDATE entities SET data=? WHERE id=?', (canonical(value), row['id']))
    for row in connection.execute('SELECT id FROM workspaces').fetchall():
        Store.event(connection, row['id'], 'system:restore', 'backup.restored', 'authorization-reset')
    for row in connection.execute('SELECT id,user FROM vault_spaces').fetchall():
        Store.event(connection, 'personal:'+row['user'], 'system:restore', 'vault.recovery_restored', row['id'])
    for row in connection.execute('SELECT id,workspace FROM team_vaults').fetchall():
        Store.event(connection, row['workspace'], 'system:restore', 'team_vault.recovery_restored', row['id'])


def restore_backup(archive, key_file, destination):
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise BackupError('Restore requires a new, nonexistent directory; live data is never overwritten.')
    parent = destination.parent.resolve(strict=True)
    # Resolve the parent once; staging and final directory share a filesystem.
    destination = parent / destination.name
    encrypted = read_bounded(archive, MAX_BYTES + 36)
    if encrypted[:8] != MAGIC or len(encrypted) < 36:
        raise BackupError('Unsupported or truncated backup file.')
    try:
        payload = AESGCM(load_key(key_file)).decrypt(encrypted[8:20], encrypted[20:], MAGIC)
    except InvalidTag:
        raise BackupError('Backup authentication failed: wrong key or changed file.') from None
    try:
        length = struct.unpack('>I', payload[:4])[0]
        if not 0 < length <= 4096:
            raise ValueError()
        manifest = json.loads(payload[4:4 + length])
        server_key = payload[4 + length:48 + length]
        database_bytes = payload[48 + length:]
        if (set(manifest) != {'format', 'schema', 'created_at', 'database_bytes'} or
                manifest['format'] != 1 or type(manifest['schema']) is not int or manifest['schema'] not in SUPPORTED_SCHEMAS or
                manifest['database_bytes'] != len(database_bytes) or
                not database_bytes.startswith(b'SQLite format 3\x00')):
            raise ValueError()
    except (ValueError, TypeError, KeyError, struct.error):
        raise BackupError('Invalid backup contents.') from None
    # Fixed filenames, no archive extraction. Never touch a live destination.
    with tempfile.TemporaryDirectory(prefix='.sentinel-restore-', dir=parent) as temporary:
        stage = Path(temporary) / 'data'
        stage.mkdir(mode=0o700)
        private_write(stage / 'sentinelops.db', database_bytes)
        private_write(stage / '.encryption-key', server_key)
        # Validate the archive's original schema before any migration. No
        # supplied schema marker may hide missing tables or a future version.
        initial = sqlite3.connect(stage / 'sentinelops.db')
        try:
            source_schema = validate_database(initial, server_key)
            if source_schema != manifest['schema']:
                raise BackupError('Backup manifest and database schema differ.')
        finally:
            initial.close()
        if source_schema < SCHEMA:
            Store(stage / 'sentinelops.db')
        connection = sqlite3.connect(stage / 'sentinelops.db')
        try:
            validate_database(connection, server_key)
            connection.row_factory = sqlite3.Row
            with connection:
                suspend_authorizations(connection)
            connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            connection.execute('PRAGMA journal_mode=DELETE')
        finally:
            connection.close()
        # On Windows rename refuses existing destinations (also recheck for POSIX).
        if destination.exists() or destination.is_symlink():
            raise BackupError('Restore destination appeared during validation.')
        stage.rename(destination)
    return {'created_at': manifest['created_at'], 'schema': SCHEMA, 'source_schema': source_schema, 'authorization_reset': True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    key = commands.add_parser('init-key', help='Create a private backup key file; never prints it.')
    key.add_argument('--key-file', required=True)
    backup = commands.add_parser('create', help='Encrypt a consistent live SQLite snapshot and server key.')
    backup.add_argument('--data-dir', required=True)
    backup.add_argument('--key-file', required=True)
    backup.add_argument('--output', required=True)
    restore = commands.add_parser('restore', help='Restore to a new directory with active authorizations revoked.')
    restore.add_argument('--input', required=True)
    restore.add_argument('--key-file', required=True)
    restore.add_argument('--destination', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'init-key':
            init_key(args.key_file)
        elif args.command == 'create':
            create_backup(args.data_dir, args.key_file, args.output)
        else:
            restore_backup(args.input, args.key_file, args.destination)
    except (OSError, ValueError, sqlite3.Error, InvalidToken):
        # Exception text can contain SQL, record contents or file paths. Keep CLI generic.
        parser.exit(1, 'Backup operation failed. Check inputs, matching schema/key, size and destination permissions. No live data was overwritten.\n')
    print('Completed. Key material and database contents were not printed.')


if __name__ == '__main__':
    main()
