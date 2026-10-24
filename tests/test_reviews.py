import json
from unittest.mock import patch

from backend.store import Store
from backend.app import Settings,create_app
from fastapi.testclient import TestClient
from test_platform import system,post,data,workflow_provider,invited

SOURCE='import hashlib\ndef login(password):\n return hashlib.sha256(password.encode()).hexdigest()\n# fixture-private-source'


def queued(app,client,**changes):
    body={'workspace_id':client.get('/api/me').json()['workspace'],'name':'Combined review','authorized':True,'checks':[
        {'action':'python','content':SOURCE,'authorized':True},
        {'action':'python','content':'eval(user_input)\nexec(user_input)','authorized':True}],**changes}
    with patch.object(app.state.executor,'submit') as submit:
        response=post(client,'/security-reviews',body)
    assert response.status_code==200,response.text
    return response.json(),submit.call_args.args


def run(arguments):arguments[0](*arguments[1:])


def test_multi_check_review_records_real_children_and_one_approved_ai_job_without_raw_content(system):
    app,client,_=system;app.state.settings.groq_key='fixture-only';app.state.agent_transport=workflow_provider()
    review,arguments=queued(app,client,ai_triage=True)
    assert 'fixture-private-source' not in json.dumps(data(client))
    # Reservation prevents another operation/AI run racing the approved review.
    assert post(client,'/operations',{'action':'python','content':'pass','authorized':True}).status_code==409
    run(arguments)
    value=data(client);review=value['security_reviews'][0]
    assert review['status']=='complete' and review['assessment_status']=='complete' and review['triage_status']=='complete'
    assert len(value['operations'])==2 and all(o['review_id']==review['id'] for o in value['operations'])
    assert len(value['jobs'])==1 and len(value['tasks'])==len(review['finding_ids'])==3
    assert value['audit']['valid'] and 'fixture-private-source' not in json.dumps(value)
    assert all('content' not in step for step in review['checks'])
    report=client.get('/api/report').json()
    assert report['version']==app.version and report['security_reviews'][0]['id']==review['id']
    run(arguments)
    assert len(data(client)['operations'])==2 and len(data(client)['jobs'])==1


def test_review_prevalidation_and_permissions_do_not_start_partial_unapproved_work(system):
    app,client,_=system
    workspace=client.get('/api/me').json()['workspace']
    valid={'action':'python','content':'pass','authorized':True}
    for changes in ({'authorized':False},{'checks':[valid,{**valid,'authorized':False}]},
                    {'checks':[valid,{'action':'website','target':'unapproved.example','authorized':True}]},
                    {'checks':[valid]*7},{'checks':[{**valid,'ai_triage':True}]}):
        body={'workspace_id':workspace,'name':'Rejected review','authorized':True,'checks':[valid],**changes}
        assert post(client,'/security-reviews',body).status_code in {422,503}
    assert post(client,'/security-reviews',{'workspace_id':workspace,'name':'No provider','authorized':True,'checks':[valid],'ai_triage':True}).status_code==503
    assert not data(client)['security_reviews'] and not data(client)['operations']
    viewer=invited(app,client,'viewer','viewer-review@example.test')
    assert post(viewer,'/security-reviews',{'workspace_id':workspace,'name':'Denied','authorized':True,'checks':[valid]}).status_code==403


def test_review_scope_cannot_follow_a_session_into_a_different_workspace(system):
    app,client,_=system
    original=client.get('/api/me').json()['workspace']
    review,arguments=queued(app,client)
    other=post(client,'/workspaces',{'name':'Other review workspace'}).json()['id']
    post(client,'/workspaces/'+other+'/switch',{})
    assert data(client)['security_reviews']==[]
    assert post(client,'/security-reviews/'+review['id']+'/cancel',{}).status_code==404
    assert post(client,'/security-reviews',{'workspace_id':original,'name':'Old draft','authorized':True,'checks':[{'action':'python','content':'pass','authorized':True}]}).status_code==409
    run(arguments)
    assert not data(client)['operations']


def test_cancel_stops_remaining_checks_but_preserves_an_already_completed_child(system):
    app,client,_=system;review,arguments=queued(app,client)
    actual=app.state.review_runner.execute
    def execute(*args):
        actual(*args)
        assert post(client,'/security-reviews/'+review['id']+'/cancel',{}).status_code==200
    app.state.review_runner.execute=execute
    run(arguments);value=data(client)
    assert value['security_reviews'][0]['status']=='cancelled'
    assert len(value['operations'])==1 and value['operations'][0]['status']=='complete'
    assert value['security_reviews'][0]['finding_ids']==value['operations'][0]['finding_ids']
    assert value['security_reviews'][0]['checks'][1]['status']=='cancelled' and not value['jobs']


def test_removed_permissions_and_cancelled_approval_cannot_run_later(system):
    app,client,_=system;review,arguments=queued(app,client)
    with app.state.store.connect(write=True) as c:c.execute("UPDATE members SET role='viewer'")
    run(arguments)
    assert data(client)['security_reviews'][0]['status']=='interrupted' and not data(client)['operations']
    with app.state.store.connect(write=True) as c:c.execute("UPDATE members SET role='owner'")
    review,arguments=queued(app,client)
    assert post(client,'/security-reviews/'+review['id']+'/cancel',{}).status_code==200
    run(arguments);assert not data(client)['operations']


def test_remote_timeout_is_unassessed_and_stops_the_child(system):
    from test_platform import PASSWORD
    app,client,_=system
    device=post(client,'/device-connections',{'label':'Scoped test device','password':PASSWORD,'targets':['127.0.0.1']})
    assert device.status_code==200,device.text
    # Device registration returns the selected public device ID separately from its bearer.
    identifier=device.json()['id']
    review,arguments=queued(app,client,checks=[{'action':'device','device_id':identifier,'target':'127.0.0.1','ports':[8110],'authorized':True}])
    app.state.review_runner.wait_seconds=0;run(arguments)
    value=data(client)
    assert value['security_reviews'][0]['status']=='partial'
    assert value['security_reviews'][0]['checks'][0]['status']=='unassessed'
    assert value['operations'][0]['status']=='cancelled' and not value['findings']


def test_cancel_revokes_a_real_paired_child_lease_and_rejects_late_results(system):
    from test_platform import PASSWORD
    app,client,_=system
    device=post(client,'/device-connections',{'label':'Review device','password':PASSWORD,'targets':['127.0.0.1']}).json()
    review,arguments=queued(app,client,checks=[{'action':'device','device_id':device['id'],'target':'127.0.0.1','ports':[8110],'authorized':True}])
    claimed={}
    def pause(_):
        response=client.post('/api/device-agent/poll',json={},headers={'Authorization':'Bearer '+device['token']})
        assert response.status_code==200,response.text
        claimed.update(response.json())
        assert post(client,'/security-reviews/'+review['id']+'/cancel',{}).status_code==200
    app.state.review_runner.pause=pause;run(arguments)
    assert claimed.get('operation'),claimed
    job=claimed['operation']
    result=client.post('/api/device-agent/result',headers={'Authorization':'Bearer '+device['token']},json={'operation_id':job['id'],'lease':job['lease'],'observations':[{'host':'127.0.0.1','port':8110,'status':'open'}]})
    assert result.status_code==409,result.text
    assert not data(client)['scans'] and not data(client)['findings']


def test_restart_interrupts_review_and_remote_review_child_without_replaying(system):
    app,client,path=system;review,arguments=queued(app,client)
    workspace=client.get('/api/me').json()['workspace']
    with app.state.store.connect(write=True) as c:
        value=Store.get(c,workspace,'security_reviews',review['id']);value['status']='running'
        value['checks'][0].update(status='running',operation_id='remote-review-child')
        Store.put(c,workspace,'security_reviews',value)
        Store.put(c,workspace,'operations',{'id':'remote-review-child','status':'queued','device_id':'paired','review_id':review['id']})
    reopened=create_app(Settings(data_dir=path,groq_key=''))
    with TestClient(reopened):
        with reopened.state.store.connect() as c:
            current=Store.get(c,workspace,'security_reviews',review['id'])
            child=Store.get(c,workspace,'operations','remote-review-child')
    assert current['status']=='interrupted' and current['checks'][0]['status']=='interrupted' and child['status']=='interrupted'
