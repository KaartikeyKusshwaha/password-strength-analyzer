import hashlib
import json
from pathlib import Path

import pytest
from backend.helper_status import status
from companion.helper_artifacts import source_inventory
from test_platform import system


def helper(tmp_path):
    artifact=tmp_path/'SentinelOpsDeviceHelper.exe'
    payload=b'disposable helper fixture'*50000
    artifact.write_bytes(payload)
    metadata=dict(sources=source_inventory('windows-x64'),version='0.2.0',platform='windows-x64',sha256=hashlib.sha256(payload).hexdigest(),bytes=len(payload),signed=False)
    (tmp_path/'helper-manifest.json').write_text(json.dumps(metadata))
    return artifact,metadata


def test_windows_helper_requires_actual_hash_not_only_size(tmp_path):
    artifact,metadata=helper(tmp_path)
    assert status(tmp_path)==dict(available=True,version='0.2.0',platform='windows-x64',sha256=metadata['sha256'],bytes=metadata['bytes'],signed=False)
    artifact.write_bytes(b'x'*metadata['bytes'])
    assert status(tmp_path)=={'available':False}


@pytest.mark.parametrize('field,value',[('platform','macos-arm64'),('bytes',1_200_000.0),('signed',True),('sha256','a'*63),('version',None)])
def test_invalid_windows_metadata_is_unavailable(tmp_path,field,value):
    _,metadata=helper(tmp_path)
    metadata[field]=value
    (tmp_path/'helper-manifest.json').write_text(json.dumps(metadata))
    assert status(tmp_path)=={'available':False}


@pytest.mark.parametrize('name',['helper-manifest.json','SentinelOpsDeviceHelper.exe'])
def test_linked_windows_helper_inputs_are_unavailable(tmp_path,monkeypatch,name):
    helper(tmp_path)
    original=Path.is_symlink
    monkeypatch.setattr(Path,'is_symlink',lambda path:path==tmp_path/name or original(path))
    assert status(tmp_path)=={'available':False}


def test_oversized_manifest_is_not_read(tmp_path,monkeypatch):
    helper(tmp_path)
    manifest=tmp_path/'helper-manifest.json';manifest.write_bytes(b' '*16385)
    original=Path.read_text
    def read(path,*args,**kwargs):
        assert path!=manifest,'oversized manifest must be rejected before parsing'
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'read_text',read)
    assert status(tmp_path)=={'available':False}


def test_download_route_refuses_changed_helper(system,tmp_path,monkeypatch):
    from backend import helper_status
    _,owner,_=system
    artifact,metadata=helper(tmp_path)
    monkeypatch.setattr(helper_status,'ROOT',tmp_path)
    monkeypatch.setattr(helper_status,'status',lambda:status(tmp_path))
    downloaded=owner.get('/api/device-helper/windows')
    assert downloaded.status_code==200
    assert hashlib.sha256(downloaded.content).hexdigest()==metadata['sha256']
    artifact.write_bytes(b'x'*metadata['bytes'])
    denied=owner.get('/api/device-helper/windows')
    assert denied.status_code==404 and denied.json()['detail']=='Windows helper build unavailable'


@pytest.mark.parametrize('platform',['windows-x64','macos-arm64','macos-x86_64'])
def test_helper_becomes_unavailable_after_cloud_origin_source_changes(tmp_path,platform):
    from companion.helper_artifacts import SOURCE_ROOT
    from backend.helper_status import macos_status
    sources=tmp_path/'sources';sources.mkdir()
    inventory=source_inventory(platform)
    for name in inventory:(sources/name).write_bytes((SOURCE_ROOT/name).read_bytes())
    payload=b'disposable executable fixture'*50000
    name='SentinelOpsDeviceHelper.exe' if platform=='windows-x64' else 'SentinelOpsDeviceHelper-'+platform+'.zip'
    (tmp_path/name).write_bytes(payload)
    metadata=dict(version='0.2.0',platform=platform,sha256=hashlib.sha256(payload).hexdigest(),bytes=len(payload),signed=False,sources=inventory)
    if platform!='windows-x64':metadata['notarized']=False
    (tmp_path/'helper-manifest.json').write_text(json.dumps(metadata))
    check=status if platform=='windows-x64' else macos_status
    assert check(tmp_path,source_root=sources)['available']
    for name in inventory:
        path=sources/name
        path.write_bytes(path.read_bytes().replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))
    assert check(tmp_path,source_root=sources)['available']
    (sources/'helper_client.py').write_text('CLOUD_ORIGIN="https://new.example.test"')
    assert check(tmp_path,source_root=sources)=={'available':False}


@pytest.mark.parametrize('sources',[None,{}, {'../outside.py':'a'*64}])
def test_missing_or_forged_source_inventory_is_not_a_current_build(tmp_path,sources):
    _,metadata=helper(tmp_path)
    metadata['sources']=sources
    (tmp_path/'helper-manifest.json').write_text(json.dumps(metadata))
    assert status(tmp_path)=={'available':False}
