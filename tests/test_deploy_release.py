import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
from deploy.build_release import build_release
from deploy.build_provenance import source_digest,stamp


def fixture_release(tmp_path, monkeypatch):
    files = ['requirements.txt', 'run.py', 'backend/app.py', 'backend/postgres_layout.json', 'backend/public/proof.html',
             'backend/public/proof-view.js', 'backend/public/proof-view.css', 'companion/__init__.py',
             'companion/device_agent.py', 'companion/extension/sentinelops-companion.zip',
             'frontend/dist/index.html', 'frontend/dist/assets/app.js',
             'deploy/oracle/sentinelops.service', 'deploy/oracle/install.sh',
             'deploy/oracle/app.env.example', 'deploy/oracle/Caddyfile.example',
             'deploy/oracle/backup.sh', 'deploy/oracle/backup-export.sh',
             'deploy/oracle/sentinelops-backup.service', 'deploy/oracle/sentinelops-backup.timer']
    for name in files:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('public fixture', encoding='utf-8')
    monkeypatch.setattr('deploy.build_provenance.subprocess.check_output', lambda *args, **kwargs: 'a'*40)
    stamp(tmp_path,tmp_path,source_digest(tmp_path))
    return tmp_path


def test_release_excludes_operator_data_and_records_actual_payload_hashes(tmp_path, monkeypatch):
    root = fixture_release(tmp_path, monkeypatch)
    for name in ['.env','data/sentinelops.db','backend/__pycache__/cache.pyc','companion/extension/private.json','frontend/dist/assets/debug.js.map']:
        path=root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('private fixture', encoding='utf-8')
    output=root/'data/deploy/release.tar.gz'
    first=build_release(root,output)
    assert build_release(root,output)==first
    with tarfile.open(fileobj=io.BytesIO(output.read_bytes()),mode='r:gz') as archive:
        names=archive.getnames()
        assert {'backend/public/proof.html','backend/public/proof-view.js','backend/public/proof-view.css'}<=set(names)
        assert {'deploy/oracle/backup.sh','deploy/oracle/backup-export.sh','deploy/oracle/sentinelops-backup.service','deploy/oracle/sentinelops-backup.timer'}<=set(names)
        assert not any(name.startswith('data/') or name.endswith(('.env','.map','.pyc','private.json')) for name in names)
        manifest=json.load(archive.extractfile('release-manifest.json'))
        assert manifest['revision']=='a'*40
        for name,digest in manifest['files'].items():
            assert hashlib.sha256(archive.extractfile(name).read()).hexdigest()==digest


def test_missing_build_does_not_replace_existing_release(tmp_path,monkeypatch):
    root=fixture_release(tmp_path,monkeypatch)
    output=root/'release.tar.gz'
    build_release(root,output)
    before=output.read_bytes()
    (root/'frontend/dist/index.html').unlink()
    with pytest.raises(ValueError,match='missing'):
        build_release(root,output)
    assert output.read_bytes()==before


def test_linked_required_file_is_rejected(tmp_path,monkeypatch):
    root=fixture_release(tmp_path,monkeypatch)
    original=Path.is_symlink
    monkeypatch.setattr(Path,'is_symlink',lambda path:path==root/'requirements.txt' or original(path))
    with pytest.raises(ValueError,match='linked'):
        build_release(root,root/'release.tar.gz')


def test_windows_checkout_exports_linux_shell_and_service_line_endings(tmp_path,monkeypatch):
    root=fixture_release(tmp_path,monkeypatch)
    script=b'#!/usr/bin/env bash\r\nset -euo pipefail\r\n'
    service=b'[Service]\r\nUser=sentinelops\r\n'
    (root/'deploy/oracle/install.sh').write_bytes(script)
    (root/'deploy/oracle/sentinelops.service').write_bytes(service)
    (root/'build-provenance.json').unlink()
    stamp(root,root,source_digest(root))
    output=root/'release.tar.gz'
    build_release(root,output)
    with tarfile.open(output,'r:gz') as archive:
        for name,original in [('install.sh',script),('sentinelops.service',service)]:
            assert archive.extractfile('deploy/oracle/'+name).read()==original.replace(b'\r\n',b'\n')
        manifest=json.load(archive.extractfile('release-manifest.json'))
        assert manifest['files']['deploy/oracle/install.sh']==hashlib.sha256(script.replace(b'\r\n',b'\n')).hexdigest()

def test_incomplete_helper_build_is_never_published(tmp_path,monkeypatch):
    root=fixture_release(tmp_path,monkeypatch)
    helper=root/'companion/helper-dist';helper.mkdir()
    (helper/'SentinelOpsDeviceHelper.exe').write_bytes(b'build fixture')
    with pytest.raises(ValueError,match='Incomplete Windows helper'):build_release(root,root/'release.tar.gz')
    (helper/'helper-manifest.json').write_text('{}',encoding='utf-8')
    with pytest.raises(ValueError,match='unverified Windows helper'):build_release(root,root/'release.tar.gz')
    payload=b'fixture-not-real-executable'*50000
    (helper/'SentinelOpsDeviceHelper.exe').write_bytes(payload)
    metadata=dict(version='0.2.0',platform='windows-x64',sha256=hashlib.sha256(payload).hexdigest(),bytes=len(payload),signed=False)
    (helper/'helper-manifest.json').write_text(json.dumps(metadata))
    output=root/'release.tar.gz';build_release(root,output)
    with tarfile.open(output,'r:gz') as archive:
        assert 'companion/helper-dist/SentinelOpsDeviceHelper.exe' in archive.getnames()
        assert 'companion/helper-dist/helper-manifest.json' in archive.getnames()
    before=output.read_bytes()
    (helper/'SentinelOpsDeviceHelper.exe').write_bytes(b'x'*len(payload))
    with pytest.raises(ValueError,match='unverified Windows helper'):build_release(root,output)
    assert output.read_bytes()==before

def test_macos_helper_requires_matching_package_hash_and_is_allowlisted(tmp_path,monkeypatch):
    root=fixture_release(tmp_path,monkeypatch);helper=root/'companion/helper-macos-dist';helper.mkdir()
    with pytest.raises(ValueError,match='macOS helper'):build_release(root,root/'release.tar.gz')
    name='SentinelOpsDeviceHelper-macos-arm64.zip';payload=b'fixture-not-real-package'*50000
    (helper/name).write_bytes(payload)
    (helper/'private.json').write_text('never package this')
    metadata=dict(version='0.2.0',platform='macos-arm64',sha256=hashlib.sha256(payload).hexdigest(),bytes=len(payload),signed=False,notarized=False)
    (helper/'helper-manifest.json').write_text(json.dumps(metadata))
    output=root/'release.tar.gz';build_release(root,output)
    with tarfile.open(output,'r:gz') as archive:
        assert 'companion/helper-macos-dist/'+name in archive.getnames()
        assert 'companion/helper-macos-dist/private.json' not in archive.getnames()
    (helper/name).write_bytes(b'x'*len(payload))
    with pytest.raises(ValueError,match='macOS helper'):build_release(root,output)


@pytest.mark.parametrize('platform',['windows-x64','macos-arm64'])
def test_helper_changed_after_status_check_does_not_replace_archive(tmp_path,monkeypatch,platform):
    root=fixture_release(tmp_path,monkeypatch)
    windows=platform=='windows-x64'
    helper=root/('companion/helper-dist' if windows else 'companion/helper-macos-dist');helper.mkdir()
    name='SentinelOpsDeviceHelper.exe' if windows else 'SentinelOpsDeviceHelper-'+platform+'.zip'
    artifact=helper/name;payload=b'disposable helper fixture'*50000;artifact.write_bytes(payload)
    metadata=dict(version='0.2.0',platform=platform,sha256=hashlib.sha256(payload).hexdigest(),bytes=len(payload),signed=False)
    if not windows:metadata['notarized']=False
    (helper/'helper-manifest.json').write_text(json.dumps(metadata))
    output=root/'release.tar.gz';build_release(root,output);before=output.read_bytes()
    original=Path.read_bytes
    monkeypatch.setattr(Path,'read_bytes',lambda path:b'x'*len(payload) if path==artifact else original(path))
    with pytest.raises(ValueError,match='changed during release'):build_release(root,output)
    assert output.read_bytes()==before
