"""Version fifteen: durable client handoff scope, approvals and receipts."""
VERSION=15
COLUMNS=('id','workspace','client','person','recipient','created_by','kind','status','plan','plan_digest','approval','receipt','workflow','created_at','updated_at')


def validate_layout(c):
    if tuple(row[1] for row in c.execute('PRAGMA table_info(handoff_records)'))!=COLUMNS:
        raise ValueError('Client handoff schema is incomplete or incompatible.')


def apply(c,at):
    if not c.in_transaction:raise RuntimeError('Migration requires a transaction.')
    marked=c.execute('SELECT 1 FROM schema_migrations WHERE version=?',(VERSION,)).fetchone()
    if not marked:
        if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='handoff_records'").fetchone():raise ValueError('Unmarked client handoff migration.')
        c.execute('CREATE TABLE handoff_records(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,client TEXT NOT NULL,person TEXT,recipient TEXT NOT NULL,created_by TEXT NOT NULL,kind TEXT NOT NULL,status TEXT NOT NULL,plan TEXT NOT NULL,plan_digest TEXT NOT NULL,approval TEXT,receipt TEXT,workflow TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)')
        c.execute('CREATE INDEX handoffs_scope ON handoff_records(workspace,status)')
        c.execute('CREATE INDEX handoffs_recipient ON handoff_records(workspace,recipient)')
    validate_layout(c)
    if not marked:c.execute('INSERT INTO schema_migrations VALUES(?,?)',(VERSION,at))
