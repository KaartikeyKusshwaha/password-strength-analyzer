"""Version twelve: approval-bound access workflows and atomic local steps."""
VERSION=12
TABLES={
    'workflows':('id','workspace','client','person','created_by','status','plan','plan_digest','approval','created_at','updated_at'),
    'workflow_steps':('id','workflow','position','vault','action','status','attempts','outcome','completed_at'),
}


def validate_layout(c):
    for name,columns in TABLES.items():
        if tuple(row[1] for row in c.execute('PRAGMA table_info('+name+')'))!=columns:
            raise ValueError('Access workflow schema is incomplete or incompatible.')


def apply(c,at):
    if not c.in_transaction:raise RuntimeError('Migration requires a transaction.')
    marked=c.execute('SELECT 1 FROM schema_migrations WHERE version=?',(VERSION,)).fetchone()
    if not marked:
        if any(c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone() for name in TABLES):raise ValueError('Unmarked access workflow migration.')
        c.execute('CREATE TABLE workflows(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,client TEXT NOT NULL,person TEXT NOT NULL,created_by TEXT NOT NULL,status TEXT NOT NULL,plan TEXT NOT NULL,plan_digest TEXT NOT NULL,approval TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)')
        c.execute('CREATE INDEX workflows_scope ON workflows(workspace,status)')
        c.execute('CREATE TABLE workflow_steps(id TEXT PRIMARY KEY,workflow TEXT NOT NULL,position INTEGER NOT NULL,vault TEXT NOT NULL,action TEXT NOT NULL,status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,outcome TEXT,completed_at TEXT,UNIQUE(workflow,position))')
    validate_layout(c)
    if not marked:c.execute('INSERT INTO schema_migrations VALUES(?,?)',(VERSION,at))
