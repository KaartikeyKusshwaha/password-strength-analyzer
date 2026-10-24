from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3

import pytest
from backend.postgres import PostgresStore,translate
from backend.store import Store
from test_postgres_schema import postgres_schema


def store_for(schema):
    import psycopg.conninfo
    config=json.loads(Path(os.environ['SENTINEL_TEST_PG_CONFIG']).read_text())
    return PostgresStore(psycopg.conninfo.make_conninfo(host=config['host'],port=config['port'],dbname='postgres',user='sentinelops_migration_test',password=Path(config['password_file']).read_text()),schema=schema,allow_local=True)


def test_translation_keeps_literals_and_bound_values_separate():
    assert translate("SELECT '?' AS literal, user FROM members WHERE user=? AND role='50% ? user'")=="SELECT '?' AS literal, \"user\" FROM members WHERE \"user\"=%s AND role='50%% ? user'"
    with pytest.raises(ValueError):translate('PRAGMA table_info(users)')
    with pytest.raises(ValueError):translate("SELECT json_set(data,'$.status','x') FROM entities")


def test_hosted_tls_is_required_before_connecting():
    with pytest.raises(ValueError,match='verify-full'):PostgresStore('postgresql://test.invalid/database?sslmode=require')


def test_named_parameters_preserve_casts_literals_and_reserved_names():
    query="SELECT user FROM members WHERE user=:user AND workspace=:workspace AND role=':user 50%' AND :user::text<>'' LIMIT :limit"
    assert translate(query)=="SELECT \"user\" FROM members WHERE \"user\"=%(user)s AND workspace=%(workspace)s AND role=':user 50%%' AND %(user)s::text<>'' LIMIT %(limit)s"


def test_store_retrieval_scope_and_json_types(postgres_schema):
    _,_,_,schema=postgres_schema;store=store_for(schema)
    with store.connect(write=True) as c:
        Store.put(c,'a','items',{'id':'first','status':'active','due':2,'enabled':True})
        Store.put(c,'a','items',{'id':'second','status':'active','due':11,'enabled':False})
        Store.put(c,'b','items',{'id':'other','status':'active','due':1})
    with store.connect() as c:
        assert [item['id'] for item in Store.all(c,'a','items')]==['second','first']
        assert Store.get(c,'b','items','first') is None
        assert c.execute("SELECT id FROM entities WHERE workspace=? AND json_extract(data,'$.due')<=? ORDER BY json_extract(data,'$.due')",('a',5)).fetchone()[0]=='first'
        assert c.execute("SELECT id FROM entities WHERE workspace=? AND json_extract(data,'$.enabled')=1",('a',)).fetchone()['id']=='first'
    # Global entity ID cannot mutate another workspace's payload.
    with store.connect(write=True) as c:Store.put(c,'b','items',{'id':'first','status':'changed'})
    with store.connect() as c:assert Store.get(c,'a','items','first')['status']=='active'


def test_integrity_statement_rollback_preserves_outer_transaction(postgres_schema):
    _,_,_,schema=postgres_schema;store=store_for(schema)
    with store.connect(write=True) as c:
        c.execute('INSERT INTO members VALUES(?,?,?)',('space','person','viewer'))
        with pytest.raises(sqlite3.IntegrityError):c.execute('INSERT INTO members VALUES(?,?,?)',('space','person','owner'))
        assert c.in_transaction
        Store.event(c,'space','owner','retained','person')
    with store.connect() as c:assert Store.audit(c,'space')['valid']
    with pytest.raises(RuntimeError):
        with store.connect(write=True) as c:
            c.execute('DELETE FROM members WHERE workspace=?',('space',))
            Store.event(c,'space','owner','removed','person')
            raise RuntimeError('crash before commit')
    with store.connect() as c:
        assert c.execute('SELECT count(*) FROM members').fetchone()[0]==1
        assert len(Store.audit(c,'space')['events'])==1


def test_concurrent_writers_keep_audit_chain_and_stored_approval_atomic(postgres_schema):
    _,_,_,schema=postgres_schema;store=store_for(schema)
    def write(index):
        with store.connect(write=True) as c:Store.event(c,'space','owner','change',str(index))
    with ThreadPoolExecutor(max_workers=4) as executor:list(executor.map(write,range(16)))
    with store.connect() as c:
        audit=Store.audit(c,'space')
        assert audit['valid'] and len(audit['events'])==16


def test_read_connections_cannot_mutate(postgres_schema):
    import psycopg
    _,_,_,schema=postgres_schema;store=store_for(schema)
    with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
        with store.connect() as c:c.execute('DELETE FROM members')
