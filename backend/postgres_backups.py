"""Offline PostgreSQL export/import using authenticated SentinelOps archives.

No network route exposes these operations. Imports require an empty dedicated
schema and the matching persistent server MFA key; restore revokes authority.
"""
import argparse
from contextlib import closing,contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import time

from cryptography.fernet import Fernet
from .backups import (BackupError,MAX_BYTES,load_key,read_backup,restore_backup,
                      validate_database,write_snapshot)
from .postgres import PostgresStore
from .store import Store,SCHEMA_VERSION,canonical

MAX_ROWS=250_000


def layout():
    return json.loads(Path(__file__).with_name('postgres_layout.json').read_text())


def quote(name):return '"'+name.replace('"','""')+'"'


@contextmanager
def empty_snapshot():
    # Only an empty schema touches this temporary file. Source records are
    # copied into an in-memory connection, never a plaintext export file.
    with tempfile.TemporaryDirectory(prefix='sentinelops-pg-schema-') as directory:
        path=Path(directory)/'empty.db';Store(path)
        with closing(sqlite3.connect(path)) as source,closing(sqlite3.connect(':memory:')) as snapshot:
            source.backup(snapshot)
            for table in layout():snapshot.execute('DELETE FROM '+quote(table))
            yield snapshot


def encode_row(row):
    return canonical([{'binary':bytes(value).hex()} if isinstance(value,(bytes,memoryview)) else value for value in row]).encode()


def digest_rows(rows,*,ordered=False):
    encoded=[encode_row(row) for row in rows]
    if not ordered:encoded.sort()
    digest=hashlib.sha256()
    for row in encoded:digest.update(row);digest.update(b'\n')
    return len(encoded),digest.hexdigest()


def export_backup(store,server_key,key_file,output):
    Fernet(server_key)
    if Path(output).resolve()==Path(key_file).resolve():raise BackupError('Keep the archive and key separate.')
    backup_key=load_key(key_file);started=time.monotonic();size=0;rows=0
    with empty_snapshot() as snapshot,store.connect() as connection:
        connection.connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
        for table,columns in layout().items():
            names=','.join(map(quote,columns))
            order='_sentinel_order' if table in {'entities','members'} else columns[0]
            # A named cursor bounds client buffering across the whole table.
            with connection.connection.cursor(name='sentinelops_backup_rows') as cursor:
                cursor.execute('SELECT '+names+' FROM '+quote(table)+' ORDER BY '+quote(order))
                for record in cursor:
                    rows+=1;size+=len(encode_row(record))
                    if rows>MAX_ROWS or size>MAX_BYTES or time.monotonic()-started>120:
                        raise BackupError('Snapshot exceeded its size or time budget.')
                    snapshot.execute('INSERT INTO '+quote(table)+'('+names+') VALUES('+','.join('?' for _ in columns)+')',record)
        snapshot.commit()
        schema=validate_database(snapshot,server_key)
        database_bytes=snapshot.serialize()
    return write_snapshot(database_bytes,server_key,backup_key,schema,output)


def import_backup(store,archive,key_file,server_key):
    manifest,archive_key,_,_=read_backup(archive,key_file)
    if not secrets.compare_digest(archive_key,server_key):raise BackupError('Persistent server key does not match the archive.')
    Fernet(server_key)
    # Reuse the existing validated migrations and authority-reset protocol.
    # Its private temporary restore includes only encrypted vault/MFA values,
    # account hashes and metadata; it is removed after the transaction closes.
    with tempfile.TemporaryDirectory(prefix='sentinelops-pg-import-') as directory:
        restored=Path(directory)/'restored'
        restore_backup(archive,key_file,restored)
        with closing(sqlite3.connect(restored/'sentinelops.db')) as source,store.connect(write=True) as target:
            if validate_database(source,server_key)!=SCHEMA_VERSION:raise BackupError('Matching current schema required.')
            for table in layout():
                if table!='schema_migrations' and target.execute('SELECT 1 FROM '+quote(table)+' LIMIT 1').fetchone():
                    raise BackupError('Import requires an empty target; existing records are never overwritten.')
            target.execute('DELETE FROM schema_migrations')
            total=0
            for table,columns in layout().items():
                names=','.join(map(quote,columns))
                query='SELECT '+names+' FROM '+quote(table)+' ORDER BY rowid'
                expected=[]
                for row in source.execute(query):
                    total+=1
                    if total>MAX_ROWS:raise BackupError('Import exceeds the supported row count.')
                    target.execute('INSERT INTO '+quote(table)+'('+names+') VALUES('+','.join('?' for _ in columns)+')',row)
                    expected.append(row)
                order='_sentinel_order' if table in {'entities','members'} else columns[0]
                # Compare canonical ordered values after insertion, including
                # ciphertext, revisions, IDs and audit sequence numbers.
                actual=target.execute('SELECT '+names+' FROM '+quote(table)+' ORDER BY '+quote(order))
                ordered=table in {'entities','members'}
                if digest_rows(expected,ordered=ordered)!=digest_rows((tuple(row.values) for row in actual),ordered=ordered):
                    raise BackupError('Imported row verification failed.')
            from psycopg import sql
            identities=target.execute("SELECT table_name,column_name FROM information_schema.columns WHERE table_schema=? AND is_identity='YES'",(store.schema,)).fetchall()
            for identity in identities:
                table,column=identity[:]
                sequence=target.execute('SELECT pg_get_serial_sequence(?,?)',(store.schema+'.'+table,column)).fetchone()[0]
                next_value=target.execute('SELECT COALESCE(MAX('+quote(column)+'),0)+1 FROM '+quote(table)).fetchone()[0]
                # ALTER SEQUENCE (unlike setval) participates in rollback.
                target.connection.execute(sql.SQL('ALTER SEQUENCE {} RESTART WITH {}').format(sql.Identifier(*sequence.split('.')),sql.Literal(next_value)))
            for row in target.execute('SELECT DISTINCT workspace FROM audit'):
                if not Store.audit(target,row[0])['valid']:raise BackupError('Imported audit verification failed.')
    return {'schema':SCHEMA_VERSION,'source_schema':manifest['schema'],'authorization_reset':True,'rows':total}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['export','import'])
    parser.add_argument('--key-file',required=True)
    parser.add_argument('--archive',required=True)
    args=parser.parse_args(argv)
    try:
        url=os.environ['DATABASE_URL'];server_key=os.environ['APP_ENCRYPTION_KEY'].encode('ascii')
        store=PostgresStore(url)
        if args.command=='export':export_backup(store,server_key,args.key_file,args.archive)
        else:import_backup(store,args.archive,args.key_file,server_key)
    except Exception:
        # Never print driver exceptions, connection strings, records or keys.
        parser.exit(1,'PostgreSQL archive operation failed. Check matching keys, schema, empty target and connection privately.\n')
    print('Completed. Database records and key material were not printed.')


if __name__=='__main__':main()
