import json
import time
from datetime import datetime, timezone

import pytest

from backend import access_workflows, offboarding_posture
from backend.security import digest
from backend.store import Store, now, uid
from test_access_workflows import setup, approve
from test_platform import system


def recorded(app, workspace, person, *, expires=None, at=None):
    device, asset, scan = uid(), uid(), uid()
    with app.state.store.connect(write=True) as c:
        c.execute('INSERT INTO devices(id,token,workspace,user,label,targets,expires,seen,allow_posture) VALUES(?,?,?,?,?,?,?,?,?)',
                  (device,digest(uid()),workspace,person,'PRIVATE_DEVICE_LABEL','[]',expires or time.time()+86400,time.time(),1))
        Store.put(c,workspace,'assets',dict(id=asset,device_id=device,name='PRIVATE_ASSET_NAME'))
        Store.put(c,workspace,'scans',dict(id=scan,asset_id=asset,kind='posture',at=at or now(),
                  raw='RAW_SECRET_MUST_NOT_APPEAR',posture={'platform':'macos','checks':[
                      {'id':'filevault','state':'disabled','reason':''},
                      {'id':'gatekeeper','state':'unassessed','reason':'permission_denied'},
                      {'id':'unrecognized_secret','state':'RAW_SECRET_MUST_NOT_APPEAR'},
                  ]}))
    return device, asset, scan


def evidence(client, plan):
    result=client.get('/api/access-workflows/'+plan['id']+'/report')
    assert result.status_code==200,result.text
    return result.json()['posture_snapshot']


def test_first_removal_retains_scoped_redacted_evidence_across_resume_and_later_scan(system):
    app,client,other,who,member,vaults,plan,code=setup(system)
    try:
        device,asset,scan=recorded(app,plan['workspace'],member['id'])
        recorded(app,plan['workspace'],who['id']) # other staff are excluded
        recorded(app,uid(),member['id']) # same user in another workspace is excluded
        assert evidence(client,plan) is None
        assert approve(app,client,plan,code).status_code==200
        assert evidence(client,plan) is None # approval alone is not a removal
        assert access_workflows.advance_one(app.state.store,plan['workspace'],plan['id'])
        snapshot=evidence(client,plan)
        assert snapshot['person']==member['id'] and len(snapshot['devices'])==1
        observation=snapshot['devices'][0]
        assert observation['device']==device and observation['scan']==scan
        assert observation['freshness']=='recorded_within_24h'
        assert observation['checks']==[{'id':'filevault','state':'disabled','reason':''},{'id':'gatekeeper','state':'unassessed','reason':'permission_denied'}]
        assert not observation['connection_expired']
        for secret in ('RAW_SECRET_MUST_NOT_APPEAR','PRIVATE_DEVICE_LABEL','PRIVATE_ASSET_NAME'):
            assert secret not in json.dumps(snapshot)
        with app.state.store.connect(write=True) as c:
            Store.put(c,plan['workspace'],'scans',dict(id=uid(),asset_id=asset,kind='posture',at=now(),posture={'platform':'windows','checks':[]}))
            c.execute('DELETE FROM devices WHERE id=?',(device,))
        app.state.review_runner.run_access(plan['workspace'],plan['id'])
        assert evidence(client,plan)==snapshot
        with app.state.store.connect() as c:
            events=Store.audit(c,plan['workspace'])
            assert events['valid']
            assert sum(e['action']=='access_workflow.posture_recorded' for e in events['events'])==1
        assert other.get('/api/access-workflows/'+plan['id']+'/report').status_code==403
    finally:other.close()


def test_preview_never_retains_false_removal_snapshot(system):
    app,client,other,who,member,vaults,plan,code=setup(system,dry_run=True)
    try:
        recorded(app,plan['workspace'],member['id'])
        assert approve(app,client,plan,code).status_code==200
        app.state.review_runner.run_access(plan['workspace'],plan['id'])
        assert evidence(client,plan) is None
    finally:other.close()


def test_snapshot_and_removal_roll_back_together(system,monkeypatch):
    app,client,other,who,member,vaults,plan,code=setup(system)
    try:
        recorded(app,plan['workspace'],member['id'])
        access_workflows.advance_one(app.state.store,plan['workspace'],plan['id'])
        assert evidence(client,plan) is None
        assert approve(app,client,plan,code).status_code==200
        original=offboarding_posture.capture
        def crash(*args):
            original(*args)
            raise SystemExit('interrupted before commit')
        monkeypatch.setattr(offboarding_posture,'capture',crash)
        with pytest.raises(SystemExit):access_workflows.advance_one(app.state.store,plan['workspace'],plan['id'])
        assert evidence(client,plan) is None
        assert all(other.get('/api/team-vaults/'+vault).status_code==200 for vault in vaults)
        monkeypatch.setattr(offboarding_posture,'capture',original)
        app.state.review_runner.run_access(plan['workspace'],plan['id'])
        assert len(evidence(client,plan)['devices'])==1
    finally:other.close()


def test_stale_expired_and_missing_device_evidence_stay_explicit(system):
    app,client,other,who,member,vaults,plan,code=setup(system)
    try:
        old=datetime.fromtimestamp(time.time()-90000,timezone.utc).isoformat()
        device,asset,_=recorded(app,plan['workspace'],member['id'],expires=1,at=old)
        missing,missing_asset,_=recorded(app,plan['workspace'],member['id'])
        with app.state.store.connect(write=True) as c:
            c.execute("DELETE FROM entities WHERE kind='scans' AND json_extract(data,'$.asset_id')=?",(missing_asset,))
        assert approve(app,client,plan,code).status_code==200
        app.state.review_runner.run_access(plan['workspace'],plan['id'])
        observations={d['device']:d for d in evidence(client,plan)['devices']}
        assert observations[device]['connection_expired']
        assert observations[device]['freshness']=='stale_or_unavailable'
        assert observations[missing]['scan'] is None and not observations[missing]['checks']
        assert observations[missing]['freshness']=='stale_or_unavailable'
    finally:other.close()


def test_proof_pack_opt_in_preserves_removal_snapshot_separately_from_new_observations(system,tmp_path):
    from types import SimpleNamespace
    from backend.proof_evidence import collect
    from backend.proof_pdf import render
    app,client,other,who,member,vaults,plan,code=setup(system)
    try:
        device,asset,scan=recorded(app,plan['workspace'],member['id'])
        assert approve(app,client,plan,code).status_code==200
        app.state.review_runner.run_access(plan['workspace'],plan['id'])
        snapshot=evidence(client,plan)
        with app.state.store.connect(write=True) as c:
            Store.put(c,plan['workspace'],'scans',dict(id=uid(),asset_id=asset,kind='posture',at=now(),posture={'platform':'macos','checks':[{'id':'filevault','state':'enabled','reason':''}]}))
            private,_=collect(c,plan['workspace'],plan['client'],SimpleNamespace(include_posture=False,asset_ids=[],brand='Acceptance agency'))
            assert 'posture_snapshot' not in private['offboarding'][0]
            report,source_digest=collect(c,plan['workspace'],plan['client'],SimpleNamespace(include_posture=True,asset_ids=[],brand='Acceptance agency'))
        assert report['offboarding'][0]['posture_snapshot']==snapshot
        assert report['posture'][0]['checks'][0]['state']=='enabled'
        assert report['offboarding'][0]['posture_snapshot']['devices'][0]['checks'][0]['state']=='disabled'
        report.update(id=uid(),digest=source_digest,generated_at=now())
        pdf=render(report)
        assert pdf.startswith(b'%PDF-')
        (tmp_path/'removal-proof.pdf').write_bytes(pdf)
        (tmp_path/'removal-proof.json').write_text(json.dumps(report),encoding='utf-8')
        assert 'RAW_SECRET_MUST_NOT_APPEAR' not in json.dumps(report)
    finally:other.close()


def test_large_device_scope_is_explicitly_incomplete_without_blocking_removal(system):
    app,client,other,who,member,vaults,plan,code=setup(system,vault_count=1)
    try:
        with app.state.store.connect(write=True) as c:
            for index in range(101):
                c.execute('INSERT INTO devices(id,token,workspace,user,label,targets,expires,seen,allow_posture) VALUES(?,?,?,?,?,?,?,?,?)',
                          (uid(),digest(uid()),plan['workspace'],member['id'],'Laptop '+str(index),'[]',time.time()+86400,time.time(),1))
        assert approve(app,client,plan,code).status_code==200
        app.state.review_runner.run_access(plan['workspace'],plan['id'])
        snapshot=evidence(client,plan)
        assert len(snapshot['devices'])==100 and snapshot['device_limit_reached']
        assert other.get('/api/team-vaults/'+vaults[0]).status_code==404
    finally:other.close()
