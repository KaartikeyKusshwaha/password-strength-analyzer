"""Version ten: update-status permission is separate from host-posture consent."""
VERSION=10
COLUMNS=('allow_updates','updates_enabled')

def validate_layout(c):
    info={row[1]:row for row in c.execute('PRAGMA table_info(devices)')}
    if any(name not in info or info[name][2]!='INTEGER' or info[name][3]!=1 or str(info[name][4])!='0' for name in COLUMNS):
        raise ValueError('Device update schema is incomplete or incompatible.')
    if c.execute('SELECT 1 FROM devices WHERE allow_updates NOT IN (0,1) OR updates_enabled NOT IN (0,1)').fetchone():
        raise ValueError('Invalid device update permission state.')


def apply(c,at):
    if not c.in_transaction:raise RuntimeError('Migration requires a transaction.')
    if not c.execute('SELECT 1 FROM schema_migrations WHERE version=?',(VERSION,)).fetchone():
        columns={row[1] for row in c.execute('PRAGMA table_info(devices)')}
        if any(name in columns for name in COLUMNS):
            raise ValueError('Unmarked device update migration; restore a validated store.')
        for name in COLUMNS:
            if name not in columns:
                c.execute(f'ALTER TABLE devices ADD COLUMN {name} INTEGER NOT NULL DEFAULT 0 CHECK ({name} IN (0,1))')
        validate_layout(c)
        c.execute('INSERT INTO schema_migrations VALUES(?,?)',(VERSION,at))
    else:validate_layout(c)
