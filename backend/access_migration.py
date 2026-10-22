"""Version eleven: explicit client-to-vault metadata links, no credential data."""
VERSION = 11
TABLES = {
    'clients': ('id', 'workspace', 'name', 'created_at'),
    'client_vaults': ('client', 'workspace', 'vault'),
}


def validate_layout(c):
    for name, columns in TABLES.items():
        if tuple(row[1] for row in c.execute('PRAGMA table_info(' + name + ')')) != columns:
            raise ValueError('Client access schema is incomplete or incompatible.')


def apply(c, at):
    if not c.in_transaction:
        raise RuntimeError('Migration requires a transaction.')
    marked = c.execute('SELECT 1 FROM schema_migrations WHERE version=?', (VERSION,)).fetchone()
    if not marked:
        if any(c.execute('SELECT 1 FROM sqlite_master WHERE type=? AND name=?', ('table', name)).fetchone() for name in TABLES):
            raise ValueError('Unmarked client access migration; restore a validated store.')
        c.execute('CREATE TABLE clients(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,name TEXT NOT NULL,created_at TEXT NOT NULL)')
        c.execute('CREATE INDEX clients_workspace ON clients(workspace)')
        c.execute('CREATE TABLE client_vaults(client TEXT NOT NULL,workspace TEXT NOT NULL,vault TEXT NOT NULL,PRIMARY KEY(client,vault))')
        c.execute('CREATE INDEX client_vaults_workspace ON client_vaults(workspace)')
    validate_layout(c)
    if not marked:
        c.execute('INSERT INTO schema_migrations VALUES(?,?)', (VERSION, at))
