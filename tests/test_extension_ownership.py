import json
import pytest
from backend.store import Store
from test_platform import system,post
from test_handoffs import prepare,approve_handoff,listing,signoff
from test_credential_debt import shared_connection
from test_ownership import proposal,acceptance,digest_view
from test_extension_connect import ORIGIN


def combined(browser,owner,vault,access):
    shared=shared_connection(browser,owner,vault)
    return {**access,'X-Sentinel-Vault-Token':shared['Authorization'][7:]},shared


def test_extension_transfer_uses_signed_protocol_and_completes_real_handoff(system):
    app,owner,other,recipient,who,incoming,vault,work,codes,rcodes,browser,auth,receiver,iauth,row=prepare(system,kind='client_offboard')
    try:
        assert approve_handoff(browser,auth,row,codes[1]).status_code==200
        outgoing,old_vault_auth=combined(browser,owner,vault,auth)
        receiving,recipient_vault_auth=combined(receiver,recipient,vault,iauth)
        path='/api/companion/access/vaults/'+vault+'/ownership'
        preflight=browser.options(path,headers={'Origin':ORIGIN,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization,x-sentinel-vault-token,content-type'})
        assert preflight.status_code==204 and preflight.headers['access-control-allow-origin']==ORIGIN
        assert 'x-sentinel-vault-token' in preflight.headers['access-control-allow-headers'].lower()
        unrelated=browser.options('/api/companion/access/handoffs',headers={'Origin':ORIGIN,'Access-Control-Request-Method':'POST'})
        assert 'x-sentinel-vault-token' not in unrelated.headers['access-control-allow-headers'].lower()
        assert browser.get(path,headers={**auth,'X-Sentinel-Vault-Token':recipient_vault_auth['Authorization'][7:]}).status_code==403
        assert browser.get(path,headers=auth).status_code==403
        assert browser.get(path,headers=old_vault_auth).status_code==401
        context=browser.get(path,headers=outgoing)
        assert context.status_code==200,context.text
        assert digest_view(context.json()['team'])==digest_view(owner.get('/api/team-vaults/'+vault).json())
        body=proposal(owner,who,incoming,vault)
        planned=browser.post(path,headers=outgoing,json=body)
        assert planned.status_code==200,planned.text
        current=receiver.get(path,headers=receiving).json()
        assert current['proposal']['id']==body['document']['id']
        signed=acceptance(owner,incoming,planned.json()['proposal'],{who['id']:who,incoming['id']:incoming,who['departing']['id']:who['departing']})
        completed=receiver.post(path+'/accept',headers=receiving,json=signed)
        assert completed.status_code==200,completed.text
        assert completed.json()['shared_connections_revoked']
        assert browser.get('/api/companion/vault',headers=old_vault_auth).status_code==401
        assert receiver.get('/api/companion/vault',headers=recipient_vault_auth).status_code==401
        assert browser.get(path,headers=outgoing).status_code==403
        assert owner.get('/api/team-vaults/'+vault).status_code==404
        current=listing(receiver,iauth)
        assert current['evidence']['issues']==[]
        assert signoff(receiver,iauth,current,rcodes[0]).json()['status']=='complete'
        with app.state.store.connect() as c:assert Store.audit(c,work['workspace'])['valid']
    finally:other.close();recipient.close()


def test_transfer_rejects_wrong_vault_revocation_stale_snapshot_and_policy(system):
    app,owner,other,recipient,who,incoming,vault,work,codes,rcodes,browser,auth,receiver,iauth,row=prepare(system)
    try:
        combined_auth,shared=combined(browser,owner,vault,auth)
        path='/api/companion/access/vaults/'+vault+'/ownership'
        assert browser.get(path.replace(vault,'a'*24),headers=combined_auth).status_code==403
        assert browser.get(path,headers={**combined_auth,'Origin':'chrome-extension://'+'b'*32}).status_code==401
        body=proposal(owner,who,incoming,vault)
        assert post(owner,'/team-vaults/'+vault+'/browser-policy',{'browser_fill':False}).status_code==200
        assert browser.post(path,headers=combined_auth,json=body).status_code==409
        fresh=proposal(owner,who,incoming,vault)
        assert browser.post(path,headers=combined_auth,json=fresh).status_code==200
        with app.state.store.connect(write=True) as c:c.execute("DELETE FROM companions WHERE user=? AND vault_id=?",(who['id'],vault))
        assert browser.post(path+'/'+fresh['document']['id']+'/cancel',headers=combined_auth,json={}).status_code==403
        assert owner.get('/api/team-vaults/'+vault+'/ownership').json()['proposal']['status']=='pending'
    finally:other.close();recipient.close()


def test_transfer_mutation_audit_failure_rolls_back_both_protocol_and_effects(system,monkeypatch):
    app,owner,other,recipient,who,incoming,vault,work,codes,rcodes,browser,auth,receiver,iauth,row=prepare(system)
    try:
        outgoing,_=combined(browser,owner,vault,auth);receiving,_=combined(receiver,recipient,vault,iauth)
        path='/api/companion/access/vaults/'+vault+'/ownership'
        planned=browser.post(path,headers=outgoing,json=proposal(owner,who,incoming,vault)).json()['proposal']
        signed=acceptance(owner,incoming,planned,{who['id']:who,incoming['id']:incoming,who['departing']['id']:who['departing']})
        before=owner.get('/api/team-vaults/'+vault).json()
        event=Store.event
        def interrupted(c,workspace,actor,action,target):
            event(c,workspace,actor,action,target)
            if action=='team_vault.ownership_transferred':raise RuntimeError('synthetic interrupted audit')
        monkeypatch.setattr(Store,'event',interrupted)
        with pytest.raises(RuntimeError):receiver.post(path+'/accept',headers=receiving,json=signed)
        assert owner.get('/api/team-vaults/'+vault).json()==before
        assert receiver.get(path,headers=receiving).json()['proposal']['status']=='pending'
    finally:other.close();recipient.close()
