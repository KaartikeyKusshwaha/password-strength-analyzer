"""Version thirteen: reported access metadata; never credential contents."""
VERSION=13
TABLES={'access_grants':('id','workspace','client','person','domain','account_label','role','source','state','created_by','created_at','updated_at')}


def validate_layout(c):
    for name,columns in TABLES.items():
        if tuple(row[1] for row in c.execute('PRAGMA table_info('+name+')'))!=columns:
            raise ValueError('Reported access schema is incomplete or incompatible.')


def apply(c,at):
    if not c.in_transaction:raise RuntimeError('Migration requires a transaction.')
    marked=c.execute('SELECT 1 FROM schema_migrations WHERE version=?',(VERSION,)).fetchone()
    if not marked:
        if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='access_grants'").fetchone():raise ValueError('Unmarked reported access migration.')
        c.execute('CREATE TABLE access_grants(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,client TEXT NOT NULL,person TEXT NOT NULL,domain TEXT NOT NULL,account_label TEXT NOT NULL,role TEXT NOT NULL,source TEXT NOT NULL,state TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,UNIQUE(workspace,client,person,domain,account_label,source))')
        c.execute('CREATE INDEX reported_access_scope ON access_grants(workspace,client,person)')
    validate_layout(c)
    if not marked:c.execute('INSERT INTO schema_migrations VALUES(?,?)',(VERSION,at))
