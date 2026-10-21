import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
from deploy.build_release import build_release


def fixture_release(tmp_path, monkeypatch):
    files = ['requirements.txt', 'run.py', 'backend/app.py', 'companion/__init__.py',
             'companion/device_agent.py', 'companion/extension/sentinelops-companion.zip',
             'frontend/dist/index.html', 'frontend/dist/assets/app.js',
             'deploy/oracle/sentinelops.service', 'deploy/oracle/install.sh',
             'deploy/oracle/app.env.example', 'deploy/oracle/Caddyfile.example']
    for name in files:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('public fixture', encoding='utf-8')
    monkeypatch.setattr('deploy.build_release.subprocess.check_output', lambda *args, **kwargs: 'a'*40)
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
    output=root/'release.tar.gz'
    build_release(root,output)
    with tarfile.open(output,'r:gz') as archive:
        for name,original in [('install.sh',script),('sentinelops.service',service)]:
            assert archive.extractfile('deploy/oracle/'+name).read()==original.replace(b'\r\n',b'\n')
        manifest=json.load(archive.extractfile('release-manifest.json'))
        assert manifest['files']['deploy/oracle/install.sh']==hashlib.sha256(script.replace(b'\r\n',b'\n')).hexdigest()
