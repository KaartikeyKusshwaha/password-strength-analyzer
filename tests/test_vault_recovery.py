import base64
import pytest
from backend.store import Store
from test_platform import system,post,invited,PASSWORD
from test_multivault import create,protected_envelope
from test_credential_actions import approval,browser_token,claim


def replacement(value):
    return {**value,'wrap_iv':base64.b64encode(b'n'*12).decode(),'wrapped_key':base64.b64encode(b'n'*48).decode(),'iv':base64.b64encode(b'd'*12).decode(),'ciphertext':base64.b64encode(b'new-opaque-encrypted-vault-content').decode()}


def test_rotation_cancels_only_selected_vault_actions_and_browsers_atomically(system):
    app,client,_=system;first=create(client,'Recovery vault');second=create(client,'Unaffected vault')
    for vault in (first,second):assert post(client,'/vault?vault_id='+vault['id'],dict(revision=0,envelope=protected_envelope(vault['id']))).status_code==200
    pending,_=approval(client,first['id']);running,_=approval(client,first['id']);other_action,_=approval(client,second['id'])
    browser,headers=browser_token(app,client,first['id']);other_browser,other_headers=browser_token(app,client,second['id'])
    lease=claim(browser,headers,running).json()['lease']
    payload=dict(revision=0,envelope=replacement(protected_envelope(first['id'])),rotation_reason='recovery-kit')
    assert post(client,'/vault?vault_id='+first['id'],payload).status_code==409
    assert browser.get('/api/companion/vault',headers=headers).status_code==200
    payload['revision']=1
    result=post(client,'/vault?vault_id='+first['id'],payload)
    assert result.status_code==200,result.text
    assert result.json()['revision']==2
    assert browser.get('/api/companion/vault',headers=headers).status_code==401
    assert other_browser.get('/api/companion/vault',headers=other_headers).status_code==200
    with app.state.store.connect() as c:
        rows={row['id']:dict(row) for row in c.execute('SELECT * FROM credential_actions')}
        for identifier in (pending,running):
            assert rows[identifier]['status']=='cancelled'
            assert all(rows[identifier][field] is None for field in ['lease_hash','lease_connection','lease_expires'])
        assert rows[other_action]['status']=='queued'
        me=client.get('/api/me').json()
        audit=Store.audit(c,'personal:'+me['id']);assert audit['valid']
        assert any(event['action']=='vault.recovery_kit_activated' and event['target']==first['id'] for event in audit['events'])
    assert claim(browser,headers,running).status_code==401
    assert client.get('/api/vault?vault_id='+first['id']).json()['envelope']==payload['envelope']
    assert 'vault.recovery_kit_activated' in client.get('/api/vault-activity/personal/'+first['id']).text


@pytest.mark.parametrize('reason',['recovery-current','recovery-snapshot','invalidate-recovery-kits'])
def test_supported_recovery_intents_require_changed_key_and_data_without_receiving_secrets(system,reason):
    _,client,_=system;vault=create(client,'Protected vault');value=protected_envelope(vault['id'])
    post(client,'/vault?vault_id='+vault['id'],dict(revision=0,envelope=value))
    for enc in [value,{**value,'wrapped_key':replacement(value)['wrapped_key']},{**value,'iv':replacement(value)['iv'],'ciphertext':replacement(value)['ciphertext']}]:
        assert post(client,'/vault?vault_id='+vault['id'],dict(revision=1,envelope=enc,rotation_reason=reason)).status_code==422
    response=post(client,'/vault?vault_id='+vault['id'],dict(revision=1,envelope=replacement(value),rotation_reason=reason))
    assert response.status_code==200,response.text


def test_rotation_context_owner_conflicts_and_browser_intent_refusal(system):
    app,client,_=system;vault=create(client,'Private recovery');value=protected_envelope(vault['id']);post(client,'/vault?vault_id='+vault['id'],dict(revision=0,envelope=value))
    other=invited(app,client)
    assert post(other,'/vault?vault_id='+vault['id'],dict(revision=1,envelope=replacement(value),rotation_reason='recovery-current')).status_code==404
    browser,headers=browser_token(app,client,vault['id'])
    body=dict(revision=1,envelope=replacement(value),rotation_reason='recovery-current')
    assert browser.post('/api/companion/vault',json=body,headers=headers).status_code==422
    assert post(client,'/vault?vault_id='+vault['id'],{**body,'rotation_reason':'unknown'}).status_code==422
    assert post(client,'/vault?vault_id='+vault['id'],{**body,'recovery_key':'must-not-be-accepted'}).status_code==422
    assert post(client,'/vault?vault_id='+vault['id'],{**body,'envelope':{**body['envelope'],'context':'a'*24}}).status_code==422
    assert browser.get('/api/companion/vault',headers=headers).status_code==200


def test_rotation_failure_rolls_back_ciphertext_cancellation_and_revocation(system):
    from unittest.mock import patch
    app,client,_=system;vault=create(client,'Atomic recovery');value=protected_envelope(vault['id'])
    post(client,'/vault?vault_id='+vault['id'],dict(revision=0,envelope=value))
    identifier,_=approval(client,vault['id']);browser,headers=browser_token(app,client,vault['id'])
    with patch('backend.app.record_action_cancellations',side_effect=RuntimeError('synthetic cancellation failure')):
        with pytest.raises(RuntimeError):post(client,'/vault?vault_id='+vault['id'],dict(revision=1,envelope=replacement(value),rotation_reason='recovery-current'))
    assert client.get('/api/vault?vault_id='+vault['id']).json()['envelope']==value
    assert client.get('/api/vault?vault_id='+vault['id']).json()['revision']==1
    assert browser.get('/api/companion/vault',headers=headers).status_code==200
    with app.state.store.connect() as c:
        assert c.execute('SELECT status FROM credential_actions WHERE id=?',(identifier,)).fetchone()[0]=='queued'
        assert not any(event['action']=='vault.recovered_current' for event in Store.audit(c,'personal:'+client.get('/api/me').json()['id'])['events'])
