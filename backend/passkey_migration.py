"""Version-nine schema migration and fail-closed layout validation."""
from .passkey_ceremonies import install_schema as install_ceremonies
from .passkey_credentials import install_schema as install_credentials

VERSION = 9
TABLES = {
    'passkey_ceremonies': {'token_hash','binding_hash','challenge','purpose','origin','rp_id','account','session_hash','expires'},
    'passkey_credentials': {'id','user','origin','rp_id','credential_id','public_key','sign_count','device_type','backed_up','label','created_at','last_used','revoked_at','revision'},
}


def validate_layout(c):
    for table, columns in TABLES.items():
        if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
            raise ValueError('Passkey schema is incomplete. Restore from a validated backup.')
        info = c.execute(f'PRAGMA table_info({table})').fetchall()
        primary = 'id' if table == 'passkey_credentials' else 'token_hash'
        if {row[1] for row in info} != columns or [row[1] for row in info if row[5]] != [primary]:
            raise ValueError('Passkey schema does not match this release.')
    # The global ID constraint must not be replaced by a partial/owner-only index.
    unique = []
    for row in c.execute('PRAGMA index_list(passkey_credentials)').fetchall():
        if row[2] and not row[4]:
            quoted = '"' + row[1].replace('"','""') + '"'
            unique.append([item[2] for item in c.execute(f'PRAGMA index_info({quoted})')])
    if ['credential_id'] not in unique:
        raise ValueError('Passkey credential uniqueness constraint is missing.')


def apply(c, applied_at):
    if not c.in_transaction:
        raise RuntimeError('Schema migration requires a caller transaction.')
    if not c.execute('SELECT 1 FROM schema_migrations WHERE version=?',(VERSION,)).fetchone():
        install_ceremonies(c)
        install_credentials(c)
        validate_layout(c)
        c.execute('INSERT INTO schema_migrations VALUES(?,?)',(VERSION,applied_at))
    else:
        # Never recreate a missing table under an already-applied marker.
        validate_layout(c)
