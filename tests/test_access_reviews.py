import json
import time
from datetime import datetime,timezone
from unittest.mock import patch
import httpx
from backend import agents,access_reviews,access_review_evidence
from backend.store import Store,uid,now
from test_platform import system,PASSWORD,post
from test_access_leases import prepared
from test_extension_access import connect,headers

ROOT='/api/companion/access/reviews'

def approve(browser,auth,code):
    return browser.post(ROOT+'/enable',headers=auth,json={'approved':True,'password':PASSWORD,'code':code})

def run_now(app,browser,auth):
    with patch.object(app.state.executor,'submit'):
        result=browser.post(ROOT+'/run',headers=auth,json={})
    assert result.status_code==200,result.text
    return result.json()['id']

def listing(browser,auth):return browser.get(ROOT,headers=auth).json()['reviews'][0]

def planner(calls,mutate=None,invalid=False):
    def provider(request):
        body=json.loads(request.content);calls.append(body)
        payload=json.loads(body['messages'][1]['content']);facts=payload['evidence']
        if mutate:mutate()
        recommendations=[dict(finding_id=f['finding_id'],priority_reason='Review this recorded access metadata.',actions=['Confirm whether this recorded access is still needed.'],verification='Check current access evidence and record the owner decision.') for f in facts]
        if invalid:recommendations[0]['finding_id']='invented-id'
        return httpx.Response(200,json={'choices':[{'message':{'content':json.dumps({'summary':'Review the recorded client access and shared-login debt.', 'recommendations':recommendations})}}]})
    return httpx.MockTransport(provider)

def execute(app,workspace,identifier,transport):
    with app.state.store.connect() as c:review=Store.get(c,workspace,'access_reviews',identifier)
    agents.run_job(app.state.store,workspace,review['job'],'fixture-only',app.state.settings.model,transport)

def test_weekly_pipeline_requires_consent_drafts_then_fresh_signoff_and_no_access_effects(system):
    app,owner,other,who,member,vaults,codes,browser,auth,lease=prepared(system)
    try:
        assert approve(browser,auth,codes[0]).status_code==503
        app.state.settings.groq_key='fixture-only'
        assert browser.post(ROOT+'/run',headers=auth,json={}).status_code==409
        assert approve(browser,auth,'wrong').status_code==401
        consent=approve(browser,auth,codes[0]);assert consent.status_code==200,consent.text
        assert time.time()+89*86400<consent.json()['expires']
        identifier=run_now(app,browser,auth);workspace=owner.get('/api/me').json()['workspace']
        assert browser.post(ROOT+'/run',headers=auth,json={}).status_code==409
        calls=[];execute(app,workspace,identifier,planner(calls))
        review=listing(browser,auth);assert review['status']=='ready' and review['plan'] and review['references']
        payload=json.dumps(calls)
        assert 'Offboarding client' not in payload and 'reviewer@example.test' not in payload and PASSWORD not in payload
        assert all('account_label' not in json.dumps(f) and 'client' not in f for f in json.loads(calls[0]['messages'][1]['content'])['evidence'])
        with app.state.store.connect() as c:assert not Store.all(c,workspace,'tasks')
        body=dict(approved=True,review_digest=review['review_digest'],password=PASSWORD,code=codes[1])
        assert browser.post(ROOT+'/'+identifier+'/signoff',headers=auth,json={**body,'review_digest':'0'*64}).status_code==409
        result=browser.post(ROOT+'/'+identifier+'/signoff',headers=auth,json=body);assert result.status_code==200,result.text
        assert result.json()['tasks'] and not result.json()['partial']
        first_tasks=set(result.json()['tasks'])
        assert browser.post(ROOT+'/'+identifier+'/signoff',headers=auth,json=body).status_code==409
        assert all(other.get('/api/team-vaults/'+v).status_code==200 for v in vaults)
        with app.state.store.connect() as c:
            job=Store.get(c,workspace,'jobs',review['job']);assert job['output']['status']=='draft_only'
            assert all(t['status']=='open' for t in Store.all(c,workspace,'tasks'))
            assert Store.audit(c,workspace)['valid']
        # Repeated evidence reuses open follow-up tasks from the first week.
        with app.state.store.connect(write=True) as c:
            first=Store.get(c,workspace,'access_reviews',identifier);first['expires']=0;Store.put(c,workspace,'access_reviews',first)
        second=run_now(app,browser,auth);execute(app,workspace,second,planner([]));review2=listing(browser,auth)
        result=browser.post(ROOT+'/'+second+'/signoff',headers=auth,json={**body,'code':codes[2],'review_digest':review2['review_digest']})
        assert result.status_code==200,result.text
        assert set(result.json()['tasks'])==first_tasks
        with app.state.store.connect(write=True) as c:
            assert len(Store.all(c,workspace,'tasks'))==len(result.json()['tasks'])
            job=Store.get(c,workspace,'jobs',review2['job']);progress=agents.check_progress(c,workspace,job)
            assert all(item['state']=='requires_current_access_review' for item in progress['checks'])
            assert {t['id'] for item in progress['checks'] for t in item['tasks']}==first_tasks
    finally:other.close()

def test_changed_metadata_invalid_provider_coverage_and_cancel_never_dispatch_tasks(system):
    app,owner,other,who,member,vaults,codes,browser,auth,lease=prepared(system)
    try:
        app.state.settings.groq_key='fixture-only';assert approve(browser,auth,codes[0]).status_code==200
        workspace=owner.get('/api/me').json()['workspace'];identifier=run_now(app,browser,auth)
        def mutate():
            with app.state.store.connect(write=True) as c:c.execute("UPDATE team_grants SET role='viewer' WHERE vault=? AND user=?",(vaults[0],member['id']))
        execute(app,workspace,identifier,planner([],mutate))
        assert listing(browser,auth)['status']=='failed'
        identifier=run_now(app,browser,auth);execute(app,workspace,identifier,planner([],invalid=True))
        assert listing(browser,auth)['status']=='failed'
        identifier=run_now(app,browser,auth);execute(app,workspace,identifier,planner([]));review=listing(browser,auth)
        mutate()
        with app.state.store.connect(write=True) as c:c.execute("UPDATE team_grants SET accepted=0 WHERE vault=? AND user=?",(vaults[0],member['id']))
        body=dict(approved=True,review_digest=review['review_digest'],password=PASSWORD,code=codes[1])
        assert browser.post(ROOT+'/'+identifier+'/signoff',headers=auth,json=body).status_code==409
        assert browser.post(ROOT+'/'+identifier+'/cancel',headers=auth,json={}).status_code==200
        assert browser.post(ROOT+'/'+identifier+'/signoff',headers=auth,json=body).status_code==409
        with app.state.store.connect() as c:assert not Store.all(c,workspace,'tasks')
    finally:other.close()

def test_scheduler_once_pause_restore_and_live_mfa_and_role_authority(system):
    from backend.backups import suspend_authorizations
    app,owner,other,who,member,vaults,codes,browser,auth,lease=prepared(system)
    try:
        app.state.settings.groq_key='fixture-only';config=approve(browser,auth,codes[0]).json();workspace=owner.get('/api/me').json()['workspace'];dispatched=[]
        with app.state.store.connect(write=True) as c:c.execute('UPDATE team_vaults SET rotation_required=1 WHERE id=?',(vaults[0],))
        due=config['next_due'];access_reviews.tick(app.state.store,lambda *args:dispatched.append(args),lambda:due-1);assert not dispatched
        for _ in range(2):access_reviews.tick(app.state.store,lambda *args:dispatched.append(args),lambda:due)
        assert len(dispatched)==1
        assert browser.post(ROOT+'/pause',headers=auth,json={}).status_code==200
        review=listing(browser,auth);assert review['status']=='cancelled'
        execute(app,workspace,review['id'],planner([]));assert listing(browser,auth)['status']=='cancelled'
        assert approve(browser,auth,codes[1]).status_code==200
        with app.state.store.connect(write=True) as c:c.execute('UPDATE users SET mfa=NULL WHERE id=?',(who['id'],))
        assert browser.get(ROOT,headers=auth).status_code==403
        access_reviews.tick(app.state.store,lambda *args:dispatched.append(args),lambda:time.time()+8*86400)
        with app.state.store.connect() as c:assert not access_reviews.policy(c,workspace)['enabled']
        with app.state.store.connect(write=True) as c:suspend_authorizations(c)
        with app.state.store.connect() as c:
            assert not access_reviews.policy(c,workspace)['enabled']
            assert not Store.all(c,workspace,'tasks')
        assert browser.get(ROOT,headers=auth).status_code==401
    finally:other.close()

def test_deterministic_evidence_distinguishes_stale_orphan_new_and_debt_and_bounds_omissions(system):
    app,owner,other,who,member,vaults,codes,browser,auth,lease=prepared(system)
    try:
        workspace=owner.get('/api/me').json()['workspace'];at=time.time();old=datetime.fromtimestamp(at-31*86400,timezone.utc).isoformat();orphan=uid()
        with app.state.store.connect(write=True) as c:
            c.execute("INSERT INTO team_grants VALUES(?,?,?,?,?,?)",(vaults[0],orphan,'viewer','opaque',1,old))
            c.execute('UPDATE team_vaults SET rotation_required=1 WHERE id=?',(vaults[0],))
            for index in range(25):
                identifier=uid();c.execute('INSERT INTO access_grants VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(identifier,workspace,lease['client'],member['id'],'app.example.test','Stale '+str(index),'member','manual','reported',who['id'],old,old))
            c.execute('INSERT INTO credential_exposures VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(uid(),workspace,lease['client'],vaults[0],'e'*64,'app.example.test','Recorded shared login','other','needed',None,None,who['id'],old,old,None,None))
            facts=access_review_evidence.collect(c,workspace,at-7*86400,at)
            assert facts['candidate_count']>20 and facts['omitted']==facts['candidate_count']-20
            assert {f['rule'] for f in facts['items']}=={'access_orphan','access_rotation','access_debt','access_stale'}
            assert 'inactivity' in str(facts['items']) or 'unknown' in str(facts['items'])
            c.execute("UPDATE access_grants SET role='viewer' WHERE id=(SELECT max(id) FROM access_grants)")
            assert access_review_evidence.collect(c,workspace,at-7*86400,at)['digest']!=facts['digest']
    finally:other.close()

def test_scope_isolation_legacy_reminder_consent_and_restore_cancel_live_review(system):
    from backend.backups import suspend_authorizations
    from backend.extension_connect import REMINDER_SCOPE,REMINDER_KIND
    from backend.security import digest
    app,owner,other,who,member,vaults,codes,browser,auth,lease=prepared(system)
    try:
        app.state.settings.groq_key='fixture-only';assert approve(browser,auth,codes[0]).status_code==200
        identifier=run_now(app,browser,auth);workspace=owner.get('/api/me').json()['workspace']
        preflight=browser.options(ROOT,headers={'Origin':auth['Origin'],'Access-Control-Request-Method':'GET','Access-Control-Request-Headers':'authorization'})
        assert preflight.status_code==204 and preflight.headers['access-control-allow-origin']==auth['Origin']
        reminder,pending,result=connect(app,owner,'reminders');assert result.status_code==200
        read_headers=headers(reminder,pending)
        assert reminder.get('/api/companion/reminders/context',headers=read_headers).json()['alerts'][0]['state']=='review_queued'
        assert reminder.get(ROOT,headers=read_headers).status_code==401
        assert reminder.post(ROOT+'/run',headers=read_headers,json={}).status_code==401
        with app.state.store.connect(write=True) as c:
            grant=Store.get(c,REMINDER_SCOPE,REMINDER_KIND,digest(read_headers['Authorization'][7:]));grant.pop('review_alerts');Store.put(c,REMINDER_SCOPE,REMINDER_KIND,grant)
        assert reminder.get('/api/companion/reminders/context',headers=read_headers).json()['alerts']==[]
        with app.state.store.connect() as c:
            row=Store.get(c,workspace,'access_reviews',identifier);job=Store.get(c,workspace,'jobs',row['job'])
        # Generic agent task creation cannot bypass the dedicated review sign-off.
        with app.state.store.connect(write=True) as c:
            job.update(status='failed');Store.put(c,workspace,'jobs',job)
        response=post(owner,'/agents',{'mode':'remediation','finding_ids':job['finding_ids'],'create_tasks':True,'create_investigation':False})
        assert response.status_code==409,response.text
        with app.state.store.connect(write=True) as c:suspend_authorizations(c)
        with app.state.store.connect() as c:
            assert not access_reviews.policy(c,workspace)['enabled']
            assert Store.get(c,workspace,'access_reviews',identifier)['status']=='cancelled'
            assert not Store.all(c,workspace,'tasks')
    finally:other.close()

def test_empty_review_never_calls_provider_and_expired_signoff_is_rejected(system):
    app,owner,other,who,member,vaults,codes,browser,auth,lease=prepared(system)
    try:
        app.state.settings.groq_key='fixture-only';assert approve(browser,auth,codes[0]).status_code==200
        workspace=owner.get('/api/me').json()['workspace'];old=datetime.fromtimestamp(time.time()-40*86400,timezone.utc).isoformat()
        with app.state.store.connect(write=True) as c:c.execute('UPDATE team_grants SET created_at=?',(old,))
        with patch.object(app.state.review_runner,'enqueue_access_review') as dispatch:
            identifier=run_now(app,browser,auth);dispatch.assert_not_called()
        review=listing(browser,auth);assert review['status']=='ready' and review['job'] is None and review['evidence']['candidate_count']==0
        body=dict(approved=True,review_digest=review['review_digest'],password=PASSWORD,code=codes[1])
        with app.state.store.connect(write=True) as c:
            row=Store.get(c,workspace,'access_reviews',identifier);row['expires']=0;Store.put(c,workspace,'access_reviews',row)
        assert browser.post(ROOT+'/'+identifier+'/signoff',headers=auth,json=body).status_code==409
        # The next compile cancels expired review authority, rather than replaying it.
        identifier2=run_now(app,browser,auth);assert identifier2!=identifier
        review=listing(browser,auth)
        response=browser.post(ROOT+'/'+identifier2+'/signoff',headers=auth,json={**body,'review_digest':review['review_digest']})
        assert response.status_code==200 and response.json()['tasks']==[]
        assert not response.json()['partial']
    finally:other.close()

def test_omitted_items_are_bound_and_partial_signoff_is_explicit(system):
    app,owner,other,who,member,vaults,codes,browser,auth,lease=prepared(system)
    try:
        app.state.settings.groq_key='fixture-only';assert approve(browser,auth,codes[0]).status_code==200
        workspace=owner.get('/api/me').json()['workspace'];old=datetime.fromtimestamp(time.time()-40*86400,timezone.utc).isoformat()
        with app.state.store.connect(write=True) as c:
            for index in range(24):
                c.execute('INSERT INTO access_grants VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(uid(),workspace,lease['client'],member['id'],'app.example.test','Recorded '+str(index),'member','manual','reported',who['id'],old,old))
        identifier=run_now(app,browser,auth);calls=[];execute(app,workspace,identifier,planner(calls));review=listing(browser,auth)
        assert review['evidence']['omitted']>0 and len(review['plan']['recommendations'])==20
        result=browser.post(ROOT+'/'+identifier+'/signoff',headers=auth,json=dict(approved=True,review_digest=review['review_digest'],password=PASSWORD,code=codes[1]))
        assert result.status_code==200,result.text
        assert result.json()['partial'] and len(result.json()['tasks'])==20
        next_id=run_now(app,browser,auth);execute(app,workspace,next_id,planner([]));remaining=listing(browser,auth)
        assert remaining['evidence']['reviewed_before']==20 and remaining['evidence']['omitted']==0
        assert not {item['key'] for item in review['evidence']['items']} & {item['key'] for item in remaining['evidence']['items']}
        result=browser.post(ROOT+'/'+next_id+'/signoff',headers=auth,json=dict(approved=True,review_digest=remaining['review_digest'],password=PASSWORD,code=codes[2]))
        assert result.status_code==200 and not result.json()['partial']
    finally:other.close()

def test_escalated_issue_is_not_hidden_by_an_open_task_for_a_different_category(system):
    app,client,_=system;session=client.get('/api/me').json();workspace=session['workspace']
    with app.state.store.connect(write=True) as c:
        actor=c.execute('SELECT user FROM members WHERE workspace=?',(workspace,)).fetchone()[0]
        outputs=[]
        for rule in ('access_new','access_orphan'):
            row=dict(id=uid(),created_at=now());item=dict(rule=rule,key='same-source',client=uid(),person=None,system=None,detail='Recorded metadata.')
            finding=access_review_evidence.finding(row,item);Store.put(c,workspace,'findings',finding)
            job=dict(id=uid(),mode='access_review',created_by=actor,snapshot=agents.snapshot([finding]),permissions={'create_tasks':True})
            plan={'recommendations':[{'finding_id':finding['id'],'actions':['Review access.'],'priority_reason':'Review metadata.','verification':'Check current records.'}]}
            outputs.append(agents.dispatch_work(c,workspace,job,[finding],plan))
        assert all(len(output['tasks'])==1 and not output['reused_tasks'] for output in outputs)
        assert len(Store.all(c,workspace,'tasks'))==2
