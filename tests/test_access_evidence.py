import json
from unittest.mock import patch
from backend import access_evidence
from backend.store import Store
from test_platform import system,post
from test_access_workflows import setup,approve
from test_sharing import payload,grant


def finish(app,owner,who,vaults,plan,code):
    assert approve(app,owner,plan,code).status_code==200
    app.state.review_runner.run_access(plan['workspace'],plan['id'])
    for vault in vaults:
        assert post(owner,f'/team-vaults/{vault}/rotate',{'revision':1,'payload':payload(vault,2),'grants':[grant(who,who,vault,'owner',2)]}).status_code==200
    app.state.review_runner.run_access(plan['workspace'],plan['id'])


def test_completion_schedules_three_idempotent_read_only_rechecks_and_reports_reappeared_access(system):
    app,owner,other,who,member,vaults,plan,code=setup(system)
    try:
        finish(app,owner,who,vaults,plan,code)
        path='/api/access-workflows/'+plan['id']+'/report'
        report=owner.get(path).json()
        assert report['status']=='complete' and report['audit']['valid']
        assert set(report['audit'])=={'valid','head'}
        assert [item['label'] for item in report['rechecks']]==['24h','7d','30d']
        assert all(item['current_access'] is False for item in report['vaults'])
        assert all(item['rotation_required'] is False for item in report['vaults'])
        assert 'envelope' not in str(report) and 'payload' not in str(report)
        assert other.get(path).status_code==403
        first=min(item['due'] for item in report['rechecks'])
        access_evidence.tick(app.state.store,lambda:first+1)
        checked=owner.get(path).json()['rechecks']
        assert sum(item['status']=='verified' for item in checked)==1
        assert post(owner,f'/team-vaults/{vaults[0]}/invite',grant(who,member,vaults[0],'editor',2)).status_code==200
        second=sorted(item['due'] for item in checked)[1]
        access_evidence.tick(app.state.store,lambda:second+1)
        report=owner.get(path).json()
        alert=next(item for item in report['rechecks'] if item['label']=='7d')
        assert alert['status']=='attention' and any(item['state']=='access_reappeared' for item in alert['observations'])
        with app.state.store.connect() as c:
            assert c.execute('SELECT 1 FROM team_grants WHERE vault=? AND user=?',(vaults[0],member['id'])).fetchone()
            count=c.execute("SELECT count(*) FROM audit WHERE action='access_workflow.recheck_attention'").fetchone()[0]
        access_evidence.tick(app.state.store,lambda:second+1)
        with app.state.store.connect() as c:assert c.execute("SELECT count(*) FROM audit WHERE action='access_workflow.recheck_attention'").fetchone()[0]==count
        app.state.review_runner.run_access(plan['workspace'],plan['id'])
        assert len(owner.get(path).json()['rechecks'])==3
    finally:other.close()


def test_preview_never_schedules_rechecks_and_restore_cancels_scheduled_checks(system):
    app,owner,other,who,member,vaults,plan,code=setup(system,dry_run=True)
    try:
        assert approve(app,owner,plan,code).status_code==200
        app.state.review_runner.run_access(plan['workspace'],plan['id'])
        assert owner.get('/api/access-workflows/'+plan['id']+'/report').json()['rechecks']==[]
        with app.state.store.connect(write=True) as c:
            Store.put(c,plan['workspace'],'access_rechecks',{'id':'test','workflow':plan['id'],'due':0,'status':'scheduled'})
            from backend.backups import suspend_authorizations
            suspend_authorizations(c)
        access_evidence.tick(app.state.store,lambda:10**12)
        with app.state.store.connect() as c:assert Store.get(c,plan['workspace'],'access_rechecks','test')['status']=='cancelled'
    finally:other.close()
