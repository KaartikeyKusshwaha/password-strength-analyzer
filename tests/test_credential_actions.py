import base64
import time
import sqlite3
import pytest

from fastapi.testclient import TestClient

from backend.security import digest
from backend.store import uid
from backend.companion_status import identifier as connection_id
from test_platform import PASSWORD,system,invited,post,data
from test_companions import envelope
from test_sharing import setup_identity,create,grant


def personal(client):
    identifier=post(client,'/vaults',{'name':'Action fixture'}).json()['id']
    post(client,'/vault?vault_id='+identifier,{'revision':0,'envelope':envelope()})
    return identifier


def approval(client,vault,kind='personal',count=1):
    identifier=uid()
    body={'id':identifier,'vault_id':vault,'kind':kind,'entry_count':count,'expires_at':int(time.time())+1800,'envelope':{'version':1,'iv':base64.b64encode(b'i'*12).decode(),'ciphertext':base64.b64encode(b'opaque-encrypted-selected-entry-and-origin').decode()}}
    response=post(client,'/account-actions',body)
    assert response.status_code==200,response.text
    return identifier,body


def browser_token(app,client,vault,kind='personal'):
    response=post(client,'/companions',{'kind':kind,'vault_id':vault,'password':PASSWORD,'label':'Action browser'})
    assert response.status_code==200,response.text
    return TestClient(app),{'Authorization':'Bearer '+response.json()['token']}

def test_browser_can_approve_only_its_connected_vault(system):
    app,owner,_=system;vault=personal(owner);browser,headers=browser_token(app,owner,vault)
    descriptor=browser.get('/api/companion/actions/context',headers=headers)
    assert descriptor.status_code==200 and descriptor.json()=={'actor':owner.get('/api/me').json()['id'],'vault_id':vault,'kind':'personal'}
    identifier,body=approval(owner,vault);body={**body,'id':uid()}
    assert browser.post('/api/companion/actions',headers=headers,json={**body,'vault_id':'f'*24}).status_code==403
    created=browser.post('/api/companion/actions',headers=headers,json=body);assert created.status_code==200,created.text
    assert claim(browser,headers,body['id']).status_code==200
    assert browser.post('/api/companion/actions/'+body['id']+'/cancel',headers=headers,json={}).status_code==200
    assert claim(browser,headers,body['id']).status_code==409
    with app.state.store.connect(write=True) as c:c.execute('UPDATE vault_spaces SET browser_save=0 WHERE id=?',(vault,))
    assert browser.post('/api/companion/actions',headers=headers,json={**body,'id':uid()}).status_code==403


def claim(browser,headers,identifier,resume=False):
    return browser.post('/api/companion/actions/'+identifier+'/claim',headers=headers,json={'resume':resume})


def result(browser,headers,identifier,lease,state,index=0):
    return browser.post('/api/companion/actions/'+identifier+'/result',headers=headers,json={'lease':lease,'index':index,'state':state})


def test_approval_is_private_ciphertext_only_and_bound_to_exact_vault_and_user(system):
    app,client,_=system
    first=personal(client);second=personal(client);identifier,body=approval(client,first)
    other=invited(app,client);other_vault=personal(other)
    browser,headers=browser_token(app,client,first)
    assert browser.get('/api/companion/actions',headers=headers).json()['actions'][0]['manifest']==body['envelope']
    second_browser,second_headers=browser_token(app,client,second)
    assert second_browser.get('/api/companion/actions',headers=second_headers).json()['actions']==[]
    assert claim(second_browser,second_headers,identifier).status_code==404
    assert other.get('/api/account-actions').json()['actions']==[]
    assert post(other,'/account-actions/'+identifier+'/cancel',{}).status_code==404
    assert 'manifest' not in str(data(client)) and identifier not in str(data(client)['audit']['events'])
    assert 'opaque-encrypted' not in client.get('/api/report').text
    assert browser.get('/api/account-actions',headers=headers).status_code==401
    assert post(other,'/account-actions',{**body,'id':uid(),'vault_id':first}).status_code==404


def test_claim_lease_does_not_expand_a_second_browser_token_and_outcomes_do_not_skip_preparation(system):
    app,client,_=system
    vault=personal(client);identifier,_=approval(client,vault, count=2)
    browser,headers=browser_token(app,client,vault);second,other_headers=browser_token(app,client,vault)
    claimed=claim(browser,headers,identifier);assert claimed.status_code==200,claimed.text
    lease=claimed.json()['lease']
    assert len(lease)>40 and 'lease' not in str(client.get('/api/account-actions').json())
    with app.state.store.connect() as c:
        assert c.execute('SELECT lease_hash FROM credential_actions WHERE id=?',(identifier,)).fetchone()[0]==digest(lease)
    assert claim(second,other_headers,identifier).status_code==409
    assert result(second,other_headers,identifier,lease,'prepared').status_code==409
    assert result(browser,headers,identifier,lease,'confirmed_by_user').status_code==409
    assert result(browser,headers,identifier,lease,'prepared').json()['status']=='running'
    assert result(browser,headers,identifier,lease,'confirmed_by_user').json()['status']=='running'
    assert result(browser,headers,identifier,lease,'prepared',1).json()['status']=='awaiting_confirmation'
    assert result(browser,headers,identifier,lease,'discarded',1).json()['status']=='complete'
    assert result(browser,headers,identifier,lease,'prepared',0).status_code==409


def test_lease_expiry_requires_explicit_resume_and_never_replays_work(system):
    app,client,_=system
    vault=personal(client);identifier,_=approval(client,vault);browser,headers=browser_token(app,client,vault)
    lease=claim(browser,headers,identifier).json()['lease']
    result(browser,headers,identifier,lease,'needs_attention')
    with app.state.store.connect(write=True) as c:
        c.execute('UPDATE credential_actions SET lease_expires=? WHERE id=?',(time.time()-1,identifier))
    assert browser.get('/api/companion/actions',headers=headers).json()['actions'][0]['status']=='interrupted'
    assert result(browser,headers,identifier,lease,'prepared').status_code==409
    assert claim(browser,headers,identifier).status_code==409
    resumed=claim(browser,headers,identifier,True)
    assert resumed.status_code==200 and resumed.json()['lease']!=lease
    assert resumed.json()['action']['items'][0]['state']=='needs_attention'


def test_cancellation_expiration_and_policy_changes_stop_bearer_actions(system):
    app,client,_=system
    vault=personal(client);identifier,_=approval(client,vault);browser,headers=browser_token(app,client,vault)
    lease=claim(browser,headers,identifier).json()['lease']
    assert post(client,'/account-actions/'+identifier+'/cancel',{}).status_code==200
    assert result(browser,headers,identifier,lease,'prepared').status_code==409
    identifier,_=approval(client,vault)
    with app.state.store.connect(write=True) as c:c.execute('UPDATE credential_actions SET expires_at=? WHERE id=?',(time.time()-1,identifier))
    assert browser.get('/api/companion/actions',headers=headers).json()['actions'][0]['status']=='expired'
    assert claim(browser,headers,identifier).status_code==409
    identifier,_=approval(client,vault)
    post(client,'/vaults/'+vault,{'name':'Action fixture','browser_save':False})
    assert claim(browser,headers,identifier).status_code==403
    assert browser.get('/api/companion/actions',headers=headers).status_code==403


def test_shared_actions_require_accepted_edit_access_and_offboarding_cancels_pending_work(system):
    app,client,_=system
    other=invited(app,client);owner=setup_identity(client);recipient=setup_identity(other);vault=create(client,owner)
    post(client,'/team-vaults/'+vault+'/invite',grant(owner,recipient,vault,'editor'))
    sample={'id':uid(),'vault_id':vault,'kind':'shared','entry_count':1,'expires_at':int(time.time())+1800,'envelope':{'version':1,'iv':base64.b64encode(b'i'*12).decode(),'ciphertext':base64.b64encode(b'opaque-encrypted-approval').decode()}}
    assert post(other,'/account-actions',sample).status_code==403
    post(other,'/team-vaults/'+vault+'/accept',{})
    identifier,_=approval(other,vault,'shared');browser,headers=browser_token(app,other,vault,'shared')
    lease=claim(browser,headers,identifier).json()['lease']
    assert post(client,'/members/'+recipient['id']+'/offboard',{'password':PASSWORD}).status_code==200
    assert result(browser,headers,identifier,lease,'prepared').status_code==401
    with app.state.store.connect() as c:assert c.execute('SELECT status FROM credential_actions WHERE id=?',(identifier,)).fetchone()[0]=='cancelled'


def test_invalid_bounds_and_extra_plaintext_are_rejected_without_echo(system):
    _,client,_=system
    vault=personal(client);_,body=approval(client,vault)
    for changes in [{'entry_count':21},{'expires_at':int(time.time())+7200},{'kind':'unknown'},{'password':'never-log-fixture-secret'},{'envelope':{**body['envelope'],'iv':'invalid'}}]:
        response=post(client,'/account-actions',{**body,'id':uid(),**changes})
        assert response.status_code==422,response.text
        assert 'never-log-fixture-secret' not in response.text


def test_extension_cors_is_allowed_only_on_explicit_companion_action_routes(system):
    _,client,_=system
    origin='chrome-extension://'+'a'*32
    for route in ['/api/companion/actions','/api/companion/actions/'+uid()+'/claim','/api/companion/actions/'+uid()+'/result']:
        response=client.options(route,headers={'Origin':origin})
        assert response.status_code==204 and response.headers['Access-Control-Allow-Origin']==origin
        assert client.options(route,headers={'Origin':'https://evil.example'}).status_code==403
    assert client.post('/api/account-actions',headers={'Origin':origin},json={}).status_code==403


def test_disconnect_interrupts_only_its_leases_and_requires_explicit_resume(system):
    app,client,_=system
    vault=personal(client);first,_=approval(client,vault);second,_=approval(client,vault)
    browser,headers=browser_token(app,client,vault);other,other_headers=browser_token(app,client,vault)
    lease=claim(browser,headers,first).json()['lease'];other_lease=claim(other,other_headers,second).json()['lease']
    assert result(browser,headers,first,lease,'prepared').status_code==200
    assert result(other,other_headers,second,other_lease,'prepared').status_code==200
    with app.state.store.connect() as c:
        before=dict(c.execute('SELECT * FROM credential_actions WHERE id=?',(first,)).fetchone())
    token_hash=digest(headers['Authorization'][7:])
    assert post(client,'/companions/'+connection_id(token_hash)+'/revoke',{}).status_code==200
    with app.state.store.connect() as c:
        stopped=dict(c.execute('SELECT * FROM credential_actions WHERE id=?',(first,)).fetchone())
        assert stopped['status']=='interrupted' and stopped['lease_hash'] is None and stopped['lease_connection'] is None
        assert stopped['manifest']==before['manifest'] and stopped['items']==before['items']
    assert result(browser,headers,first,lease,'confirmed_by_user').status_code==401
    assert result(other,other_headers,second,other_lease,'confirmed_by_user').json()['status']=='complete'
    assert claim(other,other_headers,first).status_code==409
    resumed=claim(other,other_headers,first,True)
    assert resumed.status_code==200 and resumed.json()['lease']!=lease
    assert resumed.json()['action']['items'][0]['state']=='prepared'
    assert result(other,other_headers,first,lease,'confirmed_by_user').status_code==409


def test_disconnect_rolls_back_report_lease_and_audit_if_token_deletion_fails(system):
    app,client,_=system
    vault=personal(client);job,_=approval(client,vault);browser,headers=browser_token(app,client,vault)
    lease=claim(browser,headers,job).json()['lease']
    assert browser.get('/api/companion/vault',headers={**headers,'X-Sentinel-Companion-Version':'0.12.7'}).status_code==200
    opaque=connection_id(digest(headers['Authorization'][7:]))
    with app.state.store.connect(write=True) as c:
        before_events=c.execute('SELECT count(*) FROM audit').fetchone()[0]
        c.execute("CREATE TRIGGER block_test_revoke BEFORE DELETE ON companions BEGIN SELECT RAISE(ABORT,'fixture deletion failure'); END")
    with pytest.raises(sqlite3.IntegrityError):post(client,'/companions/'+opaque+'/revoke',{})
    with app.state.store.connect(write=True) as c:
        row=c.execute('SELECT status,lease_hash FROM credential_actions WHERE id=?',(job,)).fetchone()
        assert row['status']=='running' and row['lease_hash']==digest(lease)
        assert c.execute('SELECT count(*) FROM audit').fetchone()[0]==before_events
        assert c.execute("SELECT count(*) FROM entities WHERE kind='companion_status'").fetchone()[0]==1
        c.execute('DROP TRIGGER block_test_revoke')
    assert post(client,'/companions/'+opaque+'/revoke',{}).status_code==200


def test_cached_bearer_authorization_cannot_claim_or_read_after_revocation(system):
    # Reproduce the boundary between bearer lookup and its later write transaction.
    from fastapi import FastAPI
    from backend.credential_actions import register
    app,client,_=system
    vault=personal(client);job,_=approval(client,vault);browser,headers=browser_token(app,client,vault)
    with app.state.store.connect() as c:
        cached=dict(c.execute('SELECT * FROM companions WHERE token=?',(digest(headers['Authorization'][7:]),)).fetchone())
    assert post(client,'/companions/'+connection_id(cached['token'])+'/revoke',{}).status_code==200
    isolated=FastAPI()
    register(isolated,app.state.store,lambda:None,lambda request:cached,lambda *args:None)
    stale=TestClient(isolated)
    assert stale.get('/api/companion/actions').status_code==401
    assert stale.get('/api/companion/actions/context').status_code==401
    assert claim(stale,{},job).status_code==401
    assert result(stale,{},job,'unused-public-fixture-lease-'*3,'prepared').status_code==401
    with app.state.store.connect() as c:
        assert c.execute('SELECT status FROM credential_actions WHERE id=?',(job,)).fetchone()[0]=='queued'
