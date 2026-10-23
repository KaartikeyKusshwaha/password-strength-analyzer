"""Pull an encrypted operator snapshot over pinned SSH and authenticate locally.

Runs on the operator computer, never as an application web route. Requires the
separately installed fixed remote exporter and a separately protected backup key.
No archive retention deletion, automatic restore, or billing service is used.
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from cryptography.fernet import InvalidToken

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from backend.backups import BackupError, MAX_BYTES, read_backup, private_write

FIELDS = {'host','user','ssh_executable','ssh_key_file','known_hosts_file','backup_key_file','destination'}
REMOTE = 'sudo -n /usr/local/sbin/sentinelops-backup-export'


def file_path(value):
    path = Path(value)
    if any(ch in str(path) for ch in ('"',"'",'\n','\r')) or not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise BackupError('Use existing absolute, non-linked operator file paths.')
    return path.resolve(strict=True)


def configuration(path):
    path = file_path(path)
    if path.stat().st_size > 16384:
        raise BackupError('Backup configuration is too large.')
    value = json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(value,dict) or set(value) != FIELDS or not all(isinstance(v,str) and v for v in value.values()):
        raise BackupError('Backup configuration fields are invalid.')
    host = value['host']
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        if len(host)>253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',host):
            raise BackupError('Use an exact IPv4 address or lowercase DNS hostname.') from None
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',value['user']):
        raise BackupError('Invalid SSH user.')
    for key in ('ssh_executable','ssh_key_file','known_hosts_file','backup_key_file'):
        value[key] = file_path(value[key])
    destination = Path(value['destination'])
    if not destination.is_absolute() or destination.is_symlink() or not destination.is_dir():
        raise BackupError('Create a private, absolute backup destination first.')
    value['destination'] = destination.resolve(strict=True)
    # Do not place either decryption or administrative key in the backup folder.
    for key in ('ssh_key_file','backup_key_file'):
        if value[key].is_relative_to(value['destination']):
            raise BackupError('Keep key files separately from backup archives.')
    if value['backup_key_file'] == value['ssh_key_file']:
        raise BackupError('Backup and SSH keys must be separate files.')
    return value


def command(config, ssh_config):
    # Ignore ambient ssh configuration, proxy commands and agent identities.
    # The server host key must already be independently verified in this file.
    return [str(config['ssh_executable']),'-F',str(ssh_config),'-T',
            '-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
            '-o',"UserKnownHostsFile='"+config['known_hosts_file'].as_posix()+"'",
            '-o','GlobalKnownHostsFile=none',
            '-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
            '-o','ClearAllForwardings=yes','-o','RequestTTY=no',
            '-o','ConnectTimeout=10','-o','ServerAliveInterval=10',
            '-o','ServerAliveCountMax=2','-i',str(config['ssh_key_file']),
            config['user']+'@'+config['host'],REMOTE]


def transfer(config, stage, *, popen=subprocess.Popen, clock=time.monotonic, sleep=time.sleep):
    """Bound ciphertext output on disk; never collect SSH stderr or secrets."""
    maximum = MAX_BYTES+36
    started = clock()
    ssh_config=stage.parent/'ssh-empty-config'
    private_write(ssh_config,b'')
    with stage.open('wb') as output:
        process = popen(command(config,ssh_config),stdin=subprocess.DEVNULL,stdout=output,
                        stderr=subprocess.DEVNULL,shell=False)
        try:
            while process.poll() is None:
                if clock()-started>180 or stage.stat().st_size>maximum:
                    raise BackupError('Backup transfer exceeded its time or size limit.')
                sleep(.1)
            if process.returncode or stage.stat().st_size>maximum:
                raise BackupError('Encrypted backup transfer failed.')
        finally:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill();process.wait(timeout=5)


def pull(config, *, transport=transfer, clock=time.time):
    destination = config['destination']
    if shutil.disk_usage(destination).free < 2*(MAX_BYTES+36):
        raise BackupError('Free at least 256 MiB before pulling a snapshot.')
    # Private temporary directory on the destination volume; no plaintext staging.
    with tempfile.TemporaryDirectory(prefix='.sentinel-pull-',dir=destination) as temporary:
        stage = Path(temporary)/'snapshot.part'
        private_write(stage,b'')
        transport(config,stage)
        manifest,_,_,archive_digest = read_backup(stage,config['backup_key_file'])
        try:
            created = datetime.fromisoformat(manifest['created_at'])
            if not created.tzinfo or not -300 <= clock()-created.timestamp() <= 86400:
                raise ValueError()
        except (ValueError,TypeError):
            raise BackupError('Snapshot timestamp is missing, future-dated or stale.') from None
        name = created.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+archive_digest[:16]+'.sentinelbackup'
        target = destination/name
        # Exclusive destination creation; never replace an earlier archive/link.
        private_write(target,stage.read_bytes())
        # Authentication includes database integrity, schema, MFA key and audit.
        result={'archive':name,'sha256':archive_digest,'schema':manifest['schema'],
                'created_at':manifest['created_at'],'verified_at':datetime.fromtimestamp(clock(),timezone.utc).isoformat(),
                'verification':'Authenticated archive, SQLite/schema/MFA-key/audit validation; not a restore drill.'}
        private_write(destination/(name+'.receipt.json'),(json.dumps(result,sort_keys=True)+'\n').encode())
        return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True)
    args=parser.parse_args(argv)
    try:
        result=pull(configuration(args.config))
    except (OSError,ValueError,subprocess.SubprocessError,sqlite3.Error,InvalidToken):
        parser.exit(1,'Off-server backup failed. Check pinned SSH, exporter, key, schema, destination space and freshness. No restore or retention deletion was performed.\n')
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
