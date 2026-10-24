import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

import pytest
from deploy.postgres_schema import prepare,ROOT


@pytest.mark.parametrize('name',['public; DROP SCHEMA public','Public','a.b','a"','a'*64,'','public','pg_catalog','information_schema'])
def test_schema_name_cannot_inject_sql_or_target_implicit_search_paths(name):
    with pytest.raises(ValueError):prepare(name)


def test_schema_export_refuses_replacing_an_existing_file(tmp_path):
    output=tmp_path/'existing.sql';output.write_text('retain prior artifact')
    result=subprocess.run([sys.executable,str(ROOT/'deploy/postgres_schema.py'),'--output',str(output)],capture_output=True,text=True)
    assert result.returncode!=0 and output.read_text()=='retain prior artifact'


def test_schema_is_reproducible_and_contains_no_bootstrap_accounts():
    first,inventory=prepare('isolated_test')
    assert prepare('isolated_test')==(first,inventory)
    assert 'INSERT INTO users' not in first
    assert 'INSERT INTO vault_spaces' not in first
    assert 'INSERT INTO team_vaults' not in first
    assert inventory==json.loads((ROOT/'backend/postgres_layout.json').read_text())


@pytest.fixture
def postgres_schema():
    config=os.getenv('SENTINEL_TEST_PG_CONFIG')
    if not config:pytest.skip('A separate disposable local PostgreSQL instance is required.')
    psycopg=pytest.importorskip('psycopg')
    value=json.loads(Path(config).read_text())
    # This fixture must never run against a hosted/customer database.
    assert value['host']=='127.0.0.1' and value['port']==15439
    password=Path(value['password_file']).read_text()
    c=psycopg.connect(host=value['host'],port=value['port'],dbname='postgres',user='sentinelops_migration_test',password=password,autocommit=True)
    schema='sentinelops_schema_test_'+secrets.token_hex(6)
    script,inventory=prepare(schema)
    try:
        c.execute(script,prepare=False)
        c.execute(psycopg.sql.SQL('SET search_path TO {}').format(psycopg.sql.Identifier(schema)))
        yield c,inventory,psycopg,schema
    finally:
        # Only the random schema created by this fixture, never public or an
        # externally supplied schema. Test records are explicitly disposable.
        c.execute(psycopg.sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(psycopg.sql.Identifier(schema)))
        c.close()


def test_real_postgres_layout_and_shared_vault_constraints(postgres_schema):
    c,inventory,pg,schema=postgres_schema
    for table,columns in inventory.items():
        actual=[row[0] for row in c.execute('SELECT column_name FROM information_schema.columns WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position',(schema,table))]
        assert [name for name in actual if name!='_sentinel_order']==columns
    assert [r[0] for r in c.execute('SELECT version FROM schema_migrations ORDER BY version')]==list(range(1,16))
    c.execute('INSERT INTO members VALUES(%s,%s,%s)',('workspace','member','viewer'))
    with pytest.raises(pg.errors.UniqueViolation):c.execute('INSERT INTO members VALUES(%s,%s,%s)',('workspace','member','owner'))
    with c.transaction():
        c.execute('INSERT INTO team_grants VALUES(%s,%s,%s,%s,%s,%s)',('vault','member','viewer','ciphertext',1,'test-time'))
    with pytest.raises(pg.errors.UniqueViolation):c.execute('INSERT INTO team_grants VALUES(%s,%s,%s,%s,%s,%s)',('vault','member','editor','other ciphertext',1,'test-time'))
    c.execute('INSERT INTO workflow_steps VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)',('step1','workflow',0,'vault','revoke','pending',0,None,None))
    with pytest.raises(pg.errors.UniqueViolation):c.execute('INSERT INTO workflow_steps VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)',('step2','workflow',0,'vault','revoke','pending',0,None,None))


def test_real_postgres_revocation_and_audit_rollback_together(postgres_schema):
    c,_,_,_=postgres_schema
    c.execute('INSERT INTO team_grants VALUES(%s,%s,%s,%s,%s,%s)',('vault','member','viewer','encrypted-envelope',1,'test-time'))
    with pytest.raises(RuntimeError,match='simulated failure'):
        with c.transaction():
            c.execute('DELETE FROM team_grants WHERE vault=%s AND "user"=%s',('vault','member'))
            c.execute('INSERT INTO audit(workspace,at,actor,action,target,previous,digest) VALUES(%s,%s,%s,%s,%s,%s,%s)',('workspace','test-time','owner','revoke','member','0'*64,'a'*64))
            raise RuntimeError('simulated failure')
    assert c.execute('SELECT count(*) FROM team_grants').fetchone()[0]==1
    assert c.execute('SELECT count(*) FROM audit').fetchone()[0]==0


def test_device_update_permissions_keep_boolean_constraints(postgres_schema):
    c,_,pg,_=postgres_schema
    c.execute('INSERT INTO devices(id,token,workspace,"user",label,targets,expires) VALUES(%s,%s,%s,%s,%s,%s,%s)',('device','token','workspace','owner','Device','[]',1.0))
    for column in ('allow_updates','updates_enabled'):
        with pytest.raises(pg.errors.CheckViolation):
            c.execute(pg.sql.SQL('UPDATE devices SET {}=2').format(pg.sql.Identifier(column)))
