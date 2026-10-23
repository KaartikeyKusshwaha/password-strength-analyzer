"""PostgreSQL transaction adapter for the application's bounded SQL vocabulary.

Schema creation is an explicit operator step. No database URLs are logged and
no fallback to local SQLite is allowed after PostgreSQL is selected.
"""
from collections.abc import Mapping
from contextlib import contextmanager
from functools import lru_cache
import json
from pathlib import Path
import re
import sqlite3

from .store import Store,SCHEMA_VERSION

NUMERIC_PATHS={'due','expires','next_due','last_checked','enabled','plan.expires_at','document.expires_at'}
JSON_PATTERN=re.compile(r"json_extract\(\s*((?:[a-z_][a-z_0-9]*\.)?(?:data|plan))\s*,\s*'\$\.([a-z_0-9.]+)'\s*\)",re.I)


def json_expression(match):
    column=match[1]
    path=match[2]
    fields=path.split('.')
    expression='('+column+'::jsonb #>> \'{'+','.join(fields)+'}\')'
    if path in NUMERIC_PATHS:
        if path=='enabled':return '(CASE '+expression+" WHEN 'true' THEN 1 WHEN 'false' THEN 0 ELSE NULL END)"
        return '('+expression+'::double precision)'
    return expression


@lru_cache(maxsize=1024)
def translate(query):
    """Translate fixed application SQL, keeping bound values entirely separate."""
    if not isinstance(query,str):raise TypeError('SQL must be a string.')
    if re.search(r'\b(PRAGMA|sqlite_master|sqlite_sequence|AUTOINCREMENT|ATTACH|DETACH)\b',query,re.I):
        raise ValueError('SQLite administrative SQL is unavailable on PostgreSQL.')
    query=JSON_PATTERN.sub(json_expression,query)
    # Tokenize literals before touching placeholders or reserved identifiers.
    # A question mark, percent sign or word inside a literal is never rewritten.
    parts=re.split(r"('(?:''|[^'])*'|\"(?:\"\"|[^\"])*\")",query)
    for index in range(0,len(parts),2):
        fragment=parts[index].replace('%','%%').replace('?','%s')
        fragment=re.sub(r'\buser\b','"user"',fragment,flags=re.I)
        fragment=re.sub(r'\browid\b','"_sentinel_order"',fragment,flags=re.I)
        parts[index]=fragment
    for index in range(1,len(parts),2):parts[index]=parts[index].replace('%','%%')
    query=''.join(parts)
    if re.match(r'\s*INSERT OR IGNORE\b',query,re.I):
        query=re.sub(r'\bINSERT OR IGNORE\b','INSERT',query,count=1,flags=re.I).rstrip().rstrip(';')+' ON CONFLICT DO NOTHING'
    query=re.sub(r'\bLIMIT -1 OFFSET\b','OFFSET',query,flags=re.I)
    # Generated insertion-order columns are deliberately absent from the fixed
    # SQLite INSERT column inventory. Existing four/three-value calls stay valid.
    query=re.sub(r'\bINSERT INTO entities\s+VALUES\b','INSERT INTO entities(id,workspace,kind,data) VALUES',query,flags=re.I)
    query=re.sub(r'\bINSERT INTO members\s+VALUES\b','INSERT INTO members(workspace,"user",role) VALUES',query,flags=re.I)
    query=query.replace('WHERE workspace=excluded.workspace AND kind=excluded.kind','WHERE entities.workspace=excluded.workspace AND entities.kind=excluded.kind')
    query=query.replace('DO UPDATE SET count=count+1','DO UPDATE SET count=attempts.count+1')
    if 'json_extract' in query.lower() or 'json_set' in query.lower():raise ValueError('Unsupported JSON query; an explicit PostgreSQL translation is required.')
    return query


class Row(Mapping):
    def __init__(self,names,values):self.names=names;self.values=values
    def __getitem__(self,key):return self.values[key] if isinstance(key,(int,slice)) else self.values[self.names.index(key)]
    def __iter__(self):return iter(self.names)
    def __len__(self):return len(self.names)


class Cursor:
    def __init__(self,cursor):self.cursor=cursor;self.names=tuple(item.name for item in cursor.description) if cursor.description else ()
    @property
    def rowcount(self):return self.cursor.rowcount
    def fetchone(self):
        value=self.cursor.fetchone()
        return None if value is None else Row(self.names,value)
    def fetchall(self):return [Row(self.names,row) for row in self.cursor.fetchall()]
    def __iter__(self):
        for row in self.cursor:yield Row(self.names,row)


class Connection:
    def __init__(self,connection):self.connection=connection
    @property
    def in_transaction(self):
        from psycopg.pq import TransactionStatus
        return self.connection.info.transaction_status==TransactionStatus.INTRANS
    def execute(self,query,parameters=()):
        import psycopg
        try:
            # Savepoints preserve SQLite's statement-level integrity failure
            # semantics for callers that intentionally catch duplicate inserts.
            with self.connection.transaction():
                return Cursor(self.connection.execute(translate(query),parameters,prepare=False))
        except psycopg.IntegrityError as error:
            raise sqlite3.IntegrityError('Database integrity constraint rejected the operation.') from error


class PostgresStore(Store):
    def __init__(self,url,*,schema='sentinelops',allow_local=False):
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        if not re.fullmatch('[a-z][a-z0-9_]{0,62}',schema) or schema in {'public','pg_catalog','information_schema'}:raise ValueError('Invalid database schema.')
        options=conninfo_to_dict(url)
        local=options.get('host') in {'127.0.0.1','localhost','::1'}
        if not (local and allow_local) and options.get('sslmode')!='verify-full':
            raise ValueError('Hosted PostgreSQL requires sslmode=verify-full.')
        self.url=url;self.schema=schema;self.path=None
        # Constructor only validates; application cold starts never recreate or
        # silently repair missing schema markers/tables.
        with self.connect() as c:
            versions=[r[0] for r in c.execute('SELECT version FROM schema_migrations ORDER BY version')]
            if versions!=list(range(1,SCHEMA_VERSION+1)):raise ValueError('PostgreSQL schema requires an explicit matching migration.')
            layout=json.loads(Path(__file__).with_name('postgres_layout.json').read_text())
            for table,expected in layout.items():
                rows=c.execute('SELECT column_name FROM information_schema.columns WHERE table_schema=? AND table_name=? ORDER BY ordinal_position',(schema,table)).fetchall()
                actual=[r[0] for r in rows if r[0]!='_sentinel_order']
                if actual!=expected:raise ValueError('PostgreSQL schema is incomplete or incompatible.')
            checks=c.execute("SELECT pg_get_constraintdef(oid) AS definition,convalidated FROM pg_constraint WHERE conrelid=?::regclass AND contype='c'",(schema+'.devices',)).fetchall()
            definitions={re.sub(r'[\s()\"]|::bigint','',row['definition']) for row in checks if row['convalidated']}
            if any('CHECK'+column+'=ANYARRAY[0,1]' not in definitions for column in ('allow_updates','updates_enabled')):
                raise ValueError('PostgreSQL device permission constraints are incomplete or incompatible.')

    @contextmanager
    def connect(self,write=False):
        import psycopg
        from psycopg import sql
        connection=psycopg.connect(self.url,connect_timeout=10,application_name='sentinelops',prepare_threshold=None)
        try:
            with connection.transaction():
                connection.execute(sql.SQL('SET LOCAL search_path TO {}').format(sql.Identifier(self.schema)))
                connection.execute("SET LOCAL lock_timeout='20s'")
                connection.execute("SET LOCAL statement_timeout='30s'")
                if write:
                    # Match SQLite BEGIN IMMEDIATE's one-writer guarantee,
                    # preserving audit chains and check-then-mutate approvals.
                    connection.execute('SELECT pg_advisory_xact_lock(741803240115)')
                else:connection.execute('SET TRANSACTION READ ONLY')
                yield Connection(connection)
        finally:connection.close()
