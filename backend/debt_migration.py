"""Version fourteen: shared-login debt metadata, never credentials."""
VERSION=14
COLUMNS=('id','workspace','client','vault','entry_ref','domain','label','platform','state','action_id','action_index','created_by','created_at','updated_at','verified_at','retired_at')
def validate_layout(c):
    if tuple(row[1] for row in c.execute('PRAGMA table_info(credential_exposures)'))!=COLUMNS:raise ValueError('Credential debt schema is incomplete or incompatible.')
def apply(c,at):
    if not c.in_transaction:raise RuntimeError('Migration requires a transaction.')
    marked=c.execute('SELECT 1 FROM schema_migrations WHERE version=?',(VERSION,)).fetchone()
    if not marked:
        if c.execute("SELECT 1 FROM sqlite_master WHERE name='credential_exposures'").fetchone():raise ValueError('Unmarked credential debt migration.')
        c.execute('CREATE TABLE credential_exposures(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,client TEXT NOT NULL,vault TEXT NOT NULL,entry_ref TEXT NOT NULL,domain TEXT NOT NULL,label TEXT NOT NULL,platform TEXT NOT NULL,state TEXT NOT NULL,action_id TEXT,action_index INTEGER,created_by TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,verified_at TEXT,retired_at TEXT,UNIQUE(workspace,client,vault,entry_ref))')
        c.execute('CREATE INDEX debt_scope ON credential_exposures(workspace,client)')
        c.execute('CREATE INDEX debt_actions ON credential_exposures(action_id,action_index)')
    validate_layout(c)
    if not marked:c.execute('INSERT INTO schema_migrations VALUES(?,?)',(VERSION,at))
