from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from unittest.mock import patch

import pytest

from backend.backups import BackupError,create_backup,init_key,restore_backup
from backend.store import Store
from deploy.offserver_backup import configuration,command,pull,transfer,REMOTE
from test_platform import system


def config(tmp_path):
    destination=tmp_path/'separate backups';destination.mkdir()
    keys=tmp_path/'private keys';keys.mkdir()
    for name in ('ssh.exe','id_ed25519','known_hosts'):(keys/name).write_text('fixture',encoding='utf-8')
    init_key(keys/'backup.key')
    value={'host':'192.0.2.1','user':'ubuntu','ssh_executable':str(keys/'ssh.exe'),
           'ssh_key_file':str(keys/'id_ed25519'),'known_hosts_file':str(keys/'known_hosts'),
           'backup_key_file':str(keys/'backup.key'),'destination':str(destination)}
    path=tmp_path/'config.json';path.write_text(json.dumps(value),encoding='utf-8')
    return path,configuration(path)


def test_authenticated_offserver_copy_is_restoreable_and_separately_receipted(system,tmp_path):
    app,client,source=system
    path,cfg=config(tmp_path)
    archive=tmp_path/'remote.sentinelbackup';create_backup(source,cfg['backup_key_file'],archive)
    original=(source/'sentinelops.db').read_bytes()
    result=pull(cfg,transport=lambda _,stage:shutil.copyfile(archive,stage))
    target=cfg['destination']/result['archive']
    assert target.read_bytes()==archive.read_bytes()
    assert json.loads(Path(str(target)+'.receipt.json').read_text())==result
    assert 'key' not in result and not list(cfg['destination'].glob('.sentinel-pull-*'))
    assert (source/'sentinelops.db').read_bytes()==original
    restored=tmp_path/'restored';restore_backup(target,cfg['backup_key_file'],restored)
    with Store(restored/'sentinelops.db').connect() as c:
        assert c.execute('SELECT count(*) FROM sessions').fetchone()[0]==0
        assert Store.audit(c,client.get('/api/me').json()['workspace'])['valid']
    with pytest.raises(FileExistsError):pull(cfg,transport=lambda _,stage:shutil.copyfile(archive,stage))
    assert target.read_bytes()==archive.read_bytes() # cannot overwrite an older copy


@pytest.mark.parametrize('failure',['tampered','wrong_key','stale','future'])
def test_untrusted_or_stale_transfers_never_become_retained_archives(system,tmp_path,failure):
    _,_,source=system
    _,cfg=config(tmp_path)
    archive=tmp_path/'remote.sentinelbackup'
    if failure in {'stale','future'}:
        stamp=datetime.fromtimestamp(time.time()+(-90000 if failure=='stale' else 3600),timezone.utc).isoformat()
        with patch('backend.backups.now',lambda:stamp):create_backup(source,cfg['backup_key_file'],archive)
    else:create_backup(source,cfg['backup_key_file'],archive)
    if failure=='tampered':
        content=bytearray(archive.read_bytes());content[-1]^=1;archive.write_bytes(content)
    if failure=='wrong_key':
        different=tmp_path/'wrong.key';init_key(different);cfg['backup_key_file']=different
    with pytest.raises(BackupError):pull(cfg,transport=lambda _,stage:shutil.copyfile(archive,stage))
    assert list(cfg['destination'].iterdir())==[]


@pytest.mark.parametrize('field,value',[('host','-oProxyCommand=bad'),('host','example.com;bad'),('user','root;bad'),('user','-option'),('extra','unexpected')])
def test_host_user_and_unknown_configuration_cannot_become_commands(tmp_path,field,value):
    path,cfg=config(tmp_path)
    raw=json.loads(path.read_text());raw[field]=value;path.write_text(json.dumps(raw))
    with pytest.raises(BackupError):configuration(path)


def test_key_material_cannot_be_stored_beside_archives(tmp_path):
    path,cfg=config(tmp_path)
    raw=json.loads(path.read_text());raw['destination']=str(cfg['backup_key_file'].parent);path.write_text(json.dumps(raw))
    with pytest.raises(BackupError,match='separately'):configuration(path)


def test_ssh_is_pinned_noninteractive_and_uses_only_fixed_exporter(tmp_path):
    _,cfg=config(tmp_path)
    args=command(cfg,tmp_path/'empty-config')
    assert args[-1]==REMOTE and args[-2]=='ubuntu@192.0.2.1'
    for option in ('BatchMode=yes','StrictHostKeyChecking=yes','IdentitiesOnly=yes','IdentityAgent=none','ClearAllForwardings=yes','GlobalKnownHostsFile=none'):
        assert option in args
    assert "UserKnownHostsFile='"+cfg['known_hosts_file'].as_posix()+"'" in args


@pytest.mark.skipif(not Path('C:/Program Files/Git/usr/bin/ssh.exe').is_file(),reason='Git Windows SSH executable unavailable')
def test_native_windows_ssh_parses_spaced_paths_and_exact_host_pinning(tmp_path):
    _,cfg=config(tmp_path)
    cfg['ssh_executable']=Path('C:/Program Files/Git/usr/bin/ssh.exe')
    empty=tmp_path/'empty config';empty.write_bytes(b'')
    args=command(cfg,empty)
    result=subprocess.run([args[0],'-G',*args[1:-1]],capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr
    assert 'userknownhostsfile '+cfg['known_hosts_file'].as_posix() in result.stdout
    assert 'batchmode yes' in result.stdout
    assert 'stricthostkeychecking true' in result.stdout


def test_hung_transfer_is_terminated_and_never_interpreted_as_shell(tmp_path):
    _,cfg=config(tmp_path);folder=tmp_path/'private stage';folder.mkdir();stage=folder/'snapshot.part';stage.write_bytes(b'')
    class Hung:
        returncode=None
        terminated=False
        def poll(self):return self.returncode
        def terminate(self):self.terminated=True;self.returncode=1
        def wait(self,timeout):return self.returncode
    process=Hung();calls=[];ticks=iter([0,181])
    def spawn(args,**kwargs):calls.append((args,kwargs));return process
    with pytest.raises(BackupError,match='limit'):transfer(cfg,stage,popen=spawn,clock=lambda:next(ticks),sleep=lambda _:None)
    assert process.terminated
    assert calls[0][1]['shell'] is False and calls[0][1]['stdin']==subprocess.DEVNULL
    assert calls[0][1]['stderr']==subprocess.DEVNULL


def test_failed_partial_transfer_cleans_up_without_success_receipt(tmp_path):
    _,cfg=config(tmp_path)
    def fail(_,stage):stage.write_bytes(b'partial ciphertext');raise BackupError('interrupted')
    with pytest.raises(BackupError):pull(cfg,transport=fail)
    assert list(cfg['destination'].iterdir())==[]


def test_transfer_preserves_binary_output_and_rejects_overlarge_completed_child(tmp_path,monkeypatch):
    _,cfg=config(tmp_path)
    folder=tmp_path/'stage';folder.mkdir();stage=folder/'snapshot.part';stage.write_bytes(b'')
    def child(args,**kwargs):
        assert args[-1]==REMOTE
        return subprocess.Popen([sys.executable,'-c',"import sys;sys.stdout.buffer.write(bytes([0,255,10,13])*16)"],**kwargs)
    transfer(cfg,stage,popen=child)
    assert stage.read_bytes()==bytes([0,255,10,13])*16
    second=tmp_path/'large-stage';second.mkdir();large=second/'snapshot.part';large.write_bytes(b'')
    monkeypatch.setattr('deploy.offserver_backup.MAX_BYTES',4)
    with pytest.raises(BackupError,match='failed|limit'):transfer(cfg,large,popen=child)
