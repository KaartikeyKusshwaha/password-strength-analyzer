"""Create a verified encrypted PostgreSQL backup on the operator's computer."""
import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from backend.backups import BackupError,MAX_BYTES,read_bounded
from backend.postgres import PostgresStore
from backend.postgres_backups import export_backup
from deploy.offserver_backup import retain_verified

FIELDS={'database_url_file','server_key_file','backup_key_file','destination'}


def configuration(path):
    value=json.loads(read_bounded(path,16*1024))
    if not isinstance(value,dict) or set(value)!=FIELDS:raise BackupError('Unexpected backup configuration fields.')
    resolved={}
    for key in FIELDS:
        target=Path(value[key])
        if not target.is_absolute() or target.is_symlink() or target.is_junction():raise BackupError('Use absolute non-linked paths.')
        if key=='destination':
            if not target.is_dir():raise BackupError('Create the private destination first.')
        elif not target.is_file():raise BackupError('Private input file is missing.')
        resolved[key]=target.resolve(strict=True)
    if len(set(resolved.values()))!=len(FIELDS):raise BackupError('Backup inputs must be separate.')
    if any(resolved[key].is_relative_to(resolved['destination']) for key in FIELDS-{'destination'}):
        raise BackupError('Keep private keys and connection settings outside the archive directory.')
    return resolved


def pull(config,*,store_factory=PostgresStore):
    destination=config['destination']
    if shutil.disk_usage(destination).free<2*(MAX_BYTES+36):raise BackupError('Free at least 256 MiB before backup.')
    # Never put credentials in process arguments, receipts or diagnostic output.
    url=read_bounded(config['database_url_file'],8192).decode('utf-8').strip()
    server_key=read_bounded(config['server_key_file'],128).strip()
    store=store_factory(url)
    with tempfile.TemporaryDirectory(prefix='.sentinel-pg-pull-',dir=destination) as temporary:
        stage=Path(temporary)/'snapshot.part'
        export_backup(store,server_key,config['backup_key_file'],stage)
        return retain_verified(stage,config['backup_key_file'],destination)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True)
    args=parser.parse_args(argv)
    try:result=pull(configuration(args.config))
    except Exception:
        parser.exit(1,'PostgreSQL off-server backup failed. Check TLS, private inputs, archive integrity and destination space. No restore or retention deletion was performed.\n')
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
