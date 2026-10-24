import base64
import sqlite3
import time

from fastapi.testclient import TestClient
from backend.store import Store
from test_platform import PASSWORD, data, invited, post, system
from test_companions import envelope


def create(client, name='Work', **properties):
    result=post(client,'/vaults',{'name':name, **properties})
    assert result.status_code == 200, result.text
    return result.json()


def test_multiple_vaults_have_independent_envelopes_revisions_and_ownership(system):
    app,client,_=system
    first=create(client,'Personal')
    second=create(client,'Client Alpha',purpose='project',lock_seconds=60,color='purple')
    assert first['is_default'] and not second['is_default']
    assert len(client.get('/api/vaults').json()['vaults']) == 2
    a,b=envelope(),envelope();b['ciphertext']=base64.b64encode(b'other-encrypted-fixture-credential-envelope').decode()
    assert post(client,'/vault?vault_id='+first['id'],{'revision':0,'envelope':a}).status_code == 200
    assert post(client,'/vault?vault_id='+second['id'],{'revision':0,'envelope':b}).status_code == 200
    assert client.get('/api/vault?vault_id='+first['id']).json()['envelope'] == a
    assert client.get('/api/vault?vault_id='+second['id']).json()['envelope'] == b
    assert client.get('/api/vault').json()['vault']['id'] == first['id']
    other=invited(app,client)
    assert other.get('/api/vaults').json()['vaults'] == []
    assert other.get('/api/vault?vault_id='+first['id']).status_code == 404
    assert post(other,'/vault?vault_id='+first['id'],{'revision':1,'envelope':b}).status_code == 404
    assert post(other,'/vaults/'+first['id'],{'name':'Stolen'}).status_code == 404
    assert 'ciphertext' not in str(data(client))
    assert 'ciphertext' not in client.get('/api/report').text


def test_browser_tokens_remain_bound_when_default_changes_and_policy_revokes_access(system):
    app,client,_=system
    first=create(client,'Browser vault')
    second=create(client,'Private work vault',browser_enabled=False)
    post(client,'/vault?vault_id='+first['id'],{'revision':0,'envelope':envelope()})
    pair=post(client,'/companions',{'label':'Scoped browser','password':PASSWORD,'vault_id':first['id']}).json()
    browser=TestClient(app);headers={'Authorization':'Bearer '+pair['token']}
    assert browser.get('/api/companion/vault',headers=headers).json()['vault']['id'] == first['id']
    assert post(client,'/vaults/'+second['id'],{'name':'Private work vault','browser_enabled':False,'is_default':True}).status_code == 200
    assert browser.get('/api/companion/vault',headers=headers).json()['vault']['id'] == first['id']
    # Query parameters cannot expand the token to another vault.
    assert browser.get('/api/companion/vault?vault_id='+second['id'],headers=headers).json()['vault']['id'] == first['id']
    assert post(client,'/companions',{'label':'Denied scope','password':PASSWORD,'vault_id':second['id']}).status_code == 409
    assert post(client,'/vaults/'+first['id'],{'name':'Browser vault','browser_save':False}).status_code == 200
    assert browser.post('/api/companion/vault',headers=headers,json={'revision':1,'envelope':envelope()}).status_code == 403
    assert post(client,'/vaults/'+first['id'],{'name':'Browser vault','browser_enabled':False}).status_code == 200
    assert browser.get('/api/companion/vault',headers=headers).status_code == 401


def test_archive_preserves_ciphertext_but_stops_writes_and_hides_browser_access(system):
    app,client,_=system
    primary=create(client,'Primary')
    archived=create(client,'Recovery',purpose='recovery',browser_enabled=False)
    assert post(client,'/vaults/'+primary['id'],{'name':'Primary','archived':True}).status_code == 409
    post(client,'/vault?vault_id='+archived['id'],{'revision':0,'envelope':envelope()})
    assert post(client,'/vaults/'+archived['id'],{'name':'Recovery','archived':True,'browser_enabled':False}).status_code == 200
    assert client.get('/api/vault?vault_id='+archived['id']).json()['envelope'] == envelope()
    assert post(client,'/vault?vault_id='+archived['id'],{'revision':1,'envelope':envelope()}).status_code == 409
    assert post(client,'/vaults/'+archived['id'],{'name':'Recovery','archived':False,'browser_enabled':False}).status_code == 200
    assert post(client,'/vault?vault_id='+archived['id'],{'revision':1,'envelope':envelope()}).status_code == 200


def test_vault_properties_validate_origins_and_lock_bounds(system):
    _,client,_=system
    for values in [{'lock_seconds':1},{'lock_seconds':10000},{'origins':['https://example.test/path']},{'origins':['https://user:pass@example.test']},{'origins':['http://example.test']}]:
        assert post(client,'/vaults',{'name':'Invalid',**values}).status_code == 422
    valid=create(client,'Scoped',origins=['https://example.test/','https://example.test'])
    assert valid['origins'] == ['https://example.test']


def protected_envelope(identifier):
    return {**envelope(),'version':2,'context':identifier,'kdf':{'algorithm':'argon2id','memory_kib':65536,'iterations':3,'parallelism':1},'wrap_iv':base64.b64encode(b'w'*12).decode(),'wrapped_key':base64.b64encode(b'k'*48).decode()}


def test_v2_context_kdf_bounds_downgrade_protection_and_rewrap_revocation(system):
    app,client,_=system
    vault=create(client,'Protected')
    payload=protected_envelope(vault['id'])
    assert post(client,'/vault?vault_id='+vault['id'],{'revision':0,'envelope':{**payload,'context':'a'*24}}).status_code == 422
    assert post(client,'/vault?vault_id='+vault['id'],{'revision':0,'envelope':{**payload,'kdf':{**payload['kdf'],'memory_kib':2147483648}}}).status_code == 422
    assert post(client,'/vault?vault_id='+vault['id'],{'revision':0,'envelope':payload}).status_code == 200
    pair=post(client,'/companions',{'label':'Protected connection','password':PASSWORD,'vault_id':vault['id']}).json()
    browser=TestClient(app);headers={'Authorization':'Bearer '+pair['token']}
    assert browser.get('/api/companion/vault',headers=headers).status_code == 200
    assert post(client,'/vault?vault_id='+vault['id'],{'revision':1,'envelope':envelope()}).status_code == 409
    replacement={**payload,'wrapped_key':base64.b64encode(b'n'*48).decode()}
    assert post(client,'/vault?vault_id='+vault['id'],{'revision':1,'envelope':replacement}).status_code == 200
    assert browser.get('/api/companion/vault',headers=headers).status_code == 401


def test_legacy_vault_migration_preserves_ciphertext_revisions_and_token_binding(tmp_path):
    path=tmp_path/'legacy.db'
    store=Store(path)
    with store.connect(write=True) as c:
        c.execute('INSERT INTO vaults VALUES(?,?,?)',('fixture-user',7,'{"version":1,"ciphertext":"fixture-opaque-ciphertext"}'))
        c.execute('INSERT INTO companions(token,user,label,expires) VALUES(?,?,?,?)',('hashed-fixture','fixture-user','Old browser',time.time()+600))
    migrated=Store(path)
    with migrated.connect() as c:
        vault=c.execute('SELECT * FROM vault_spaces').fetchone()
        assert vault['revision'] == 7 and vault['payload'] == '{"version":1,"ciphertext":"fixture-opaque-ciphertext"}'
        assert c.execute('SELECT vault_id FROM companions').fetchone()[0] == vault['id']
        assert c.execute('SELECT count(*) FROM vaults').fetchone()[0] == 0
    Store(path)
    with migrated.connect() as c:
        assert c.execute('SELECT count(*) FROM vault_spaces').fetchone()[0] == 1
