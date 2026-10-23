import json
from pathlib import Path
import shutil
import subprocess

import pytest

from deploy.build_provenance import source_digest,stamp,verify
from deploy.build_release import build_release
from deploy.prepare_release import prepare
from test_deploy_release import fixture_release


@pytest.mark.parametrize('changed',['backend/app.py','frontend/src/new.jsx','frontend/index.html','companion/extension/public/manifest.json','deploy/oracle/install.sh'])
def test_changed_source_prevents_stale_release_without_replacing_archive(tmp_path,monkeypatch,changed):
    root=fixture_release(tmp_path,monkeypatch);output=root/'release.tar.gz'
    build_release(root,output);original=output.read_bytes()
    path=root/changed;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('changed source')
    with pytest.raises(ValueError,match='provenance'):build_release(root,output)
    assert output.read_bytes()==original


@pytest.mark.parametrize('changed',['frontend/dist/index.html','frontend/dist/assets/app.js','companion/extension/sentinelops-companion.zip'])
def test_tampered_output_cannot_claim_current_source(tmp_path,monkeypatch,changed):
    root=fixture_release(tmp_path,monkeypatch)
    (root/changed).write_text('changed build')
    with pytest.raises(ValueError,match='provenance'):build_release(root,root/'release.tar.gz')


def test_missing_record_revision_change_and_during_build_source_change_fail_closed(tmp_path,monkeypatch):
    root=fixture_release(tmp_path,monkeypatch)
    monkeypatch.setattr('deploy.build_provenance.subprocess.check_output',lambda *a,**k:'b'*40)
    with pytest.raises(ValueError,match='provenance'):verify(root,root)
    (root/'build-provenance.json').unlink()
    with pytest.raises(ValueError,match='provenance'):verify(root,root)
    with pytest.raises(ValueError,match='Sources changed'):stamp(root,root,'0'*64)


def test_isolated_outputs_do_not_replace_installed_builds(tmp_path,monkeypatch):
    root=fixture_release(tmp_path/'source',monkeypatch);candidate=tmp_path/'candidate';candidate.mkdir()
    for name in ('frontend/dist','companion/extension'):
        source=root/name;target=candidate/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(source,target)
    stamp(root,candidate,source_digest(root))
    (root/'frontend/dist/index.html').write_text('installed legacy build')
    result=build_release(root,candidate/'release.tar.gz',build_root=candidate)
    assert result['revision']=='a'*40
    assert (root/'frontend/dist/index.html').read_text()=='installed legacy build'


def test_prepare_refuses_existing_directory_before_running_builds(tmp_path):
    existing=tmp_path/'existing';existing.mkdir();sentinel=existing/'keep';sentinel.write_text('unchanged')
    with pytest.raises(ValueError,match='new candidate'):prepare(tmp_path,existing,run=lambda *a,**k:pytest.fail('must not build'))
    assert sentinel.read_text()=='unchanged'


def test_failed_build_never_creates_release_or_touches_installed_outputs(tmp_path,monkeypatch):
    root=fixture_release(tmp_path/'source',monkeypatch)
    vite=root/'frontend/node_modules/vite/bin/vite.js';vite.parent.mkdir(parents=True);vite.write_text('fixture')
    def failed(*args,**kwargs):raise subprocess.CalledProcessError(1,args[0])
    candidate=tmp_path/'failed'
    with pytest.raises(subprocess.CalledProcessError):prepare(root,candidate,run=failed)
    assert not (candidate/'sentinelops-release.tar.gz').exists()
    assert (root/'frontend/dist/index.html').read_text()=='public fixture'
