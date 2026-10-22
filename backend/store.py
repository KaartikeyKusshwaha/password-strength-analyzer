"""Workspace-scoped SQLite storage. Writes and audit links share a transaction."""
import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

SCHEMA_VERSION = 14


def now():
    return datetime.now(timezone.utc).isoformat()


def uid():
    return secrets.token_hex(12)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class Store:
    def __init__(self, path):
        self.path = str(path)
        with self.connect() as c:
            if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'").fetchone():
                versions = [r[0] for r in c.execute('SELECT version FROM schema_migrations ORDER BY version')]
                if versions and (not all(type(v) is int for v in versions) or versions[-1] > SCHEMA_VERSION or versions != list(range(1,versions[-1]+1))):
                    raise ValueError('Unsupported or incomplete schema. Use a matching release and validated backup.')
            c.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,mfa TEXT,mfa_draft TEXT,mfa_step INTEGER DEFAULT -1,recovery TEXT DEFAULT '[]');
                CREATE TABLE IF NOT EXISTS workspaces(id TEXT PRIMARY KEY,name TEXT NOT NULL,demo INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS members(workspace TEXT,user TEXT,role TEXT NOT NULL,PRIMARY KEY(workspace,user));
                CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user TEXT,workspace TEXT,csrf TEXT,expires REAL,pending INTEGER DEFAULT 0);
                CREATE TABLE IF NOT EXISTS invites(token TEXT PRIMARY KEY,workspace TEXT,email TEXT,role TEXT,expires REAL);
                CREATE TABLE IF NOT EXISTS entities(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,kind TEXT NOT NULL,data TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS entities_scope ON entities(workspace,kind);
                CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,workspace TEXT,at TEXT,actor TEXT,action TEXT,target TEXT,previous TEXT,digest TEXT);
                CREATE INDEX IF NOT EXISTS audit_scope ON audit(workspace,seq);
                CREATE TABLE IF NOT EXISTS attempts(bucket TEXT PRIMARY KEY,started REAL,count INTEGER);
                CREATE TABLE IF NOT EXISTS vaults(user TEXT PRIMARY KEY,revision INTEGER NOT NULL,payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS companions(token TEXT PRIMARY KEY,user TEXT NOT NULL,label TEXT,expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,token TEXT UNIQUE NOT NULL,workspace TEXT NOT NULL,user TEXT NOT NULL,label TEXT NOT NULL,targets TEXT NOT NULL,expires REAL NOT NULL,seen REAL);
                CREATE TABLE IF NOT EXISTS vault_spaces(id TEXT PRIMARY KEY,user TEXT NOT NULL,name TEXT NOT NULL,purpose TEXT NOT NULL,color TEXT NOT NULL,lock_seconds INTEGER NOT NULL,browser_enabled INTEGER NOT NULL,browser_save INTEGER NOT NULL,browser_fill INTEGER NOT NULL,origins TEXT NOT NULL,archived INTEGER NOT NULL DEFAULT 0,is_default INTEGER NOT NULL DEFAULT 0,revision INTEGER NOT NULL DEFAULT 0,payload TEXT NOT NULL DEFAULT 'null',created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS vault_spaces_owner ON vault_spaces(user);
                CREATE UNIQUE INDEX IF NOT EXISTS vault_spaces_default ON vault_spaces(user) WHERE is_default=1;
                CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sharing_identities(user TEXT PRIMARY KEY,public TEXT NOT NULL,fingerprint TEXT NOT NULL,encrypted TEXT NOT NULL,created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS team_vaults(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,owner TEXT NOT NULL,name TEXT NOT NULL,manifest TEXT NOT NULL,payload TEXT NOT NULL,epoch INTEGER NOT NULL,revision INTEGER NOT NULL,rotation_required INTEGER NOT NULL,created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS team_grants(vault TEXT NOT NULL,user TEXT NOT NULL,role TEXT NOT NULL,envelope TEXT NOT NULL,accepted INTEGER NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(vault,user));
                CREATE INDEX IF NOT EXISTS team_grants_user ON team_grants(user,vault);
                CREATE TABLE IF NOT EXISTS credential_actions(id TEXT PRIMARY KEY,user TEXT NOT NULL,vault_id TEXT NOT NULL,kind TEXT NOT NULL,workspace TEXT,manifest TEXT NOT NULL,entry_count INTEGER NOT NULL,status TEXT NOT NULL,items TEXT NOT NULL,lease_hash TEXT,lease_connection TEXT,lease_expires REAL,created_at TEXT NOT NULL,expires_at REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS credential_actions_scope ON credential_actions(user,kind,vault_id);
                CREATE TABLE IF NOT EXISTS notification_reads(notification TEXT NOT NULL,user TEXT NOT NULL,read_at TEXT NOT NULL,PRIMARY KEY(notification,user));
            """)
            if 'vault_id' not in {row[1] for row in c.execute('PRAGMA table_info(companions)')}:
                c.execute('ALTER TABLE companions ADD COLUMN vault_id TEXT')
            companion_columns={row[1] for row in c.execute('PRAGMA table_info(companions)')}
            if 'kind' not in companion_columns:
                c.execute("ALTER TABLE companions ADD COLUMN kind TEXT NOT NULL DEFAULT 'personal'")
            if 'workspace' not in companion_columns:
                c.execute('ALTER TABLE companions ADD COLUMN workspace TEXT')
            if 'browser_policy' not in {row[1] for row in c.execute('PRAGMA table_info(team_vaults)')}:
                c.execute("ALTER TABLE team_vaults ADD COLUMN browser_policy TEXT NOT NULL DEFAULT '{\"browser_enabled\":true,\"browser_save\":true,\"browser_fill\":true,\"origins\":[],\"lock_seconds\":180}'")
            if 'allow_posture' not in {row[1] for row in c.execute('PRAGMA table_info(devices)')}:
                c.execute('ALTER TABLE devices ADD COLUMN allow_posture INTEGER NOT NULL DEFAULT 0')
            device_columns={row[1] for row in c.execute('PRAGMA table_info(devices)')}
            if 'protocol_version' not in device_columns:
                c.execute('ALTER TABLE devices ADD COLUMN protocol_version INTEGER NOT NULL DEFAULT 1')
            if 'posture_enabled' not in device_columns:
                c.execute('ALTER TABLE devices ADD COLUMN posture_enabled INTEGER NOT NULL DEFAULT 0')
            # Move legacy envelopes without decrypting, changing their keys or
            # resetting revisions. The write transaction commits all or nothing.
            for legacy in c.execute('SELECT * FROM vaults').fetchall():
                current = c.execute('SELECT id,revision,payload FROM vault_spaces WHERE user=? AND is_default=1', (legacy['user'],)).fetchone()
                if not current:
                    identifier, at = uid(), now()
                    c.execute("INSERT INTO vault_spaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (identifier,legacy['user'],'Personal','personal','moss',180,1,1,1,'[]',0,1,legacy['revision'],legacy['payload'],at,at))
                elif current['payload'] != legacy['payload'] or current['revision'] != legacy['revision']:
                    raise ValueError('Legacy and multi-vault records conflict. Migration stopped without overwriting either encrypted envelope.')
                c.execute('DELETE FROM vaults WHERE user=?', (legacy['user'],))
            c.execute('UPDATE companions SET vault_id=(SELECT id FROM vault_spaces WHERE vault_spaces.user=companions.user AND is_default=1) WHERE vault_id IS NULL')
            for version in (1,2,3,4,5,6,7,8):
                c.execute('INSERT OR IGNORE INTO schema_migrations VALUES(?,?)', (version,now()))
            from .passkey_migration import apply
            apply(c, now())
            from .device_update_migration import apply as apply_device_updates
            apply_device_updates(c, now())
            from .access_migration import apply as apply_client_access
            apply_client_access(c, now())
            from .workflow_migration import apply as apply_access_workflows
            apply_access_workflows(c, now())
            from .access_records_migration import apply as apply_access_records
            apply_access_records(c, now())
            from .debt_migration import apply as apply_debt
            apply_debt(c, now())

    @contextmanager
    def connect(self, write=False):
        c = sqlite3.connect(self.path, timeout=20)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA busy_timeout=20000")
        try:
            if write:
                c.execute("BEGIN IMMEDIATE")
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()

    @staticmethod
    def all(c, workspace, kind):
        return [json.loads(r[0]) for r in c.execute("SELECT data FROM entities WHERE workspace=? AND kind=? ORDER BY rowid DESC", (workspace, kind))]

    @staticmethod
    def get(c, workspace, kind, identifier):
        r = c.execute("SELECT data FROM entities WHERE workspace=? AND kind=? AND id=?", (workspace, kind, identifier)).fetchone()
        return json.loads(r[0]) if r else None

    @staticmethod
    def put(c, workspace, kind, value):
        c.execute("INSERT INTO entities VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data WHERE workspace=excluded.workspace AND kind=excluded.kind", (value["id"], workspace, kind, canonical(value)))
        return value

    @staticmethod
    def event(c, workspace, actor, action, target):
        prior = c.execute("SELECT digest FROM audit WHERE workspace=? ORDER BY seq DESC LIMIT 1", (workspace,)).fetchone()
        row = dict(workspace=workspace, at=now(), actor=actor, action=action, target=target, previous=prior[0] if prior else "0" * 64)
        digest = hashlib.sha256(canonical(row).encode()).hexdigest()
        c.execute("INSERT INTO audit(workspace,at,actor,action,target,previous,digest) VALUES(?,?,?,?,?,?,?)", (*row.values(), digest))

    @staticmethod
    def audit(c, workspace):
        rows = [dict(r) for r in c.execute("SELECT * FROM audit WHERE workspace=? ORDER BY seq", (workspace,))]
        previous = "0" * 64
        valid = True
        for row in rows:
            payload = {k: row[k] for k in ("workspace", "at", "actor", "action", "target", "previous")}
            valid = valid and row["previous"] == previous and hashlib.sha256(canonical(payload).encode()).hexdigest() == row["digest"]
            previous = row["digest"]
        return {"valid": valid, "head": previous, "events": rows}
