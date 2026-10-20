from fastapi.testclient import TestClient

from backend.store import uid
from test_platform import PASSWORD,system,invited,post
from test_sharing import setup_identity,create,grant,payload
from test_companions import envelope


def pair(client,identifier,kind='shared'):
    response=post(client,'/companions',{'kind':kind,'vault_id':identifier,'label':'Fixture browser','password':PASSWORD})
    assert response.status_code==200,response.text
    return {'Authorization':'Bearer '+response.json()['token']}


def shared(system,role='editor',workspace_role='reviewer'):
    app,client,_=system
    other=invited(app,client,role=workspace_role);owner=setup_identity(client);recipient=setup_identity(other);identifier=create(client,owner)
    assert post(client,'/team-vaults/'+identifier+'/invite',grant(owner,recipient,identifier,role)).status_code==200
    return app,client,other,owner,recipient,identifier


def test_shared_bearer_is_one_accepted_vault_and_own_encrypted_identity_only(system):
    app,client,other,owner,recipient,identifier=shared(system)
    assert post(other,'/companions',{'kind':'shared','vault_id':identifier,'label':'Pending browser','password':PASSWORD}).status_code==409
    post(other,'/team-vaults/'+identifier+'/accept',{})
    headers=pair(other,identifier);browser=TestClient(app)
    value=browser.get('/api/companion/vault',headers=headers).json()
    assert value['kind']=='shared' and value['vault']['id']==identifier
    assert value['sharing']['user_id']==recipient['id']
    assert value['sharing']['identity']['fingerprint']==recipient['fingerprint']
    assert 'grants' not in value['sharing']['team']
    second=create(client,owner)
    assert browser.get('/api/companion/vault?vault_id='+second,headers=headers).json()['vault']['id']==identifier
    for path in ['/api/vaults','/api/sharing/identity','/api/sharing/directory','/api/team-vaults','/api/team-vaults/'+second,'/api/workspace']:
        assert browser.get(path,headers=headers).status_code==401
    response=browser.post('/api/companion/vault',headers=headers,json={'revision':1,'envelope':payload(identifier)})
    assert response.status_code==200,response.text
    assert other.get('/api/team-vaults/'+identifier).json()['revision']==2
    assert browser.post('/api/companion/vault',headers=headers,json={'revision':1,'envelope':payload(identifier)}).status_code==409
    assert browser.post('/api/companion/vault',headers=headers,json={'revision':2,'envelope':payload(second)}).status_code==422
    assert browser.post('/api/companion/vault',headers=headers,json={'revision':2,'envelope':envelope()}).status_code==422


def test_viewer_connection_can_read_and_fill_but_cannot_write_or_change_policy(system):
    app,client,other,owner,recipient,identifier=shared(system,'viewer','viewer')
    post(other,'/team-vaults/'+identifier+'/accept',{})
    headers=pair(other,identifier);browser=TestClient(app)
    value=browser.get('/api/companion/vault',headers=headers).json()
    assert value['vault']['browser_fill'] and not value['vault']['browser_save']
    assert browser.post('/api/companion/vault',headers=headers,json={'revision':1,'envelope':payload(identifier)}).status_code==403
    assert post(other,'/team-vaults/'+identifier+'/browser-policy',{'browser_enabled':False}).status_code==403


def test_shared_browser_policy_is_live_and_disabling_revokes_tokens_permanently(system):
    app,client,other,owner,recipient,identifier=shared(system)
    post(other,'/team-vaults/'+identifier+'/accept',{})
    headers=pair(other,identifier);browser=TestClient(app)
    policy={'browser_enabled':True,'browser_fill':False,'browser_save':False,'origins':['https://example.test'],'lock_seconds':30}
    assert post(client,'/team-vaults/'+identifier+'/browser-policy',policy).status_code==200
    value=browser.get('/api/companion/vault',headers=headers).json()
    assert not value['vault']['browser_fill'] and value['vault']['origins']==['https://example.test']
    assert browser.post('/api/companion/vault',headers=headers,json={'revision':1,'envelope':payload(identifier)}).status_code==403
    assert post(client,'/team-vaults/'+identifier+'/browser-policy',{**policy,'origins':['https://example.test/path']}).status_code==422
    post(client,'/team-vaults/'+identifier+'/browser-policy',{'browser_enabled':False})
    assert browser.get('/api/companion/vault',headers=headers).status_code==401
    assert post(other,'/companions',{'kind':'shared','vault_id':identifier,'label':'Disabled browser','password':PASSWORD}).status_code==409
    post(client,'/team-vaults/'+identifier+'/browser-policy',{'browser_enabled':True})
    assert browser.get('/api/companion/vault',headers=headers).status_code==401
    assert browser.get('/api/companion/vault',headers=pair(other,identifier)).status_code==200


def test_revocation_offboarding_and_rotation_block_stale_companion_access(system):
    app,client,other,owner,recipient,identifier=shared(system)
    post(other,'/team-vaults/'+identifier+'/accept',{})
    headers=pair(other,identifier);owner_headers=pair(client,identifier);browser=TestClient(app)
    assert post(client,'/team-vaults/'+identifier+'/revoke/'+recipient['id'],{}).status_code==200
    assert browser.get('/api/companion/vault',headers=headers).status_code==401
    assert not browser.get('/api/companion/vault',headers=owner_headers).json()['vault']['browser_save']
    assert browser.post('/api/companion/vault',headers=owner_headers,json={'revision':1,'envelope':payload(identifier)}).status_code==409
    rotated={'revision':1,'payload':payload(identifier,2),'grants':[grant(owner,owner,identifier,'owner',2)]}
    assert post(client,'/team-vaults/'+identifier+'/rotate',rotated).status_code==200
    assert browser.get('/api/companion/vault',headers=owner_headers).json()['sharing']['team']['epoch']==2
    assert post(client,'/team-vaults/'+identifier+'/invite',grant(owner,recipient,identifier,'editor',2)).status_code==200
    post(other,'/team-vaults/'+identifier+'/accept',{})
    assert browser.get('/api/companion/vault',headers=headers).status_code==401
    refreshed=pair(other,identifier)
    assert browser.get('/api/companion/vault',headers=refreshed).status_code==200
    assert post(client,'/members/'+recipient['id']+'/offboard',{'password':PASSWORD}).status_code==200
    assert browser.get('/api/companion/vault',headers=refreshed).status_code==401


def test_personal_bearer_never_becomes_a_shared_bearer_even_with_matching_vault_id(system):
    app,client,_=system
    owner=setup_identity(client);identifier=create(client,owner)
    personal=post(client,'/vaults',{'name':'Personal'}).json()['id']
    post(client,'/vault?vault_id='+personal,{'revision':0,'envelope':envelope()})
    headers=pair(client,personal,'personal');browser=TestClient(app)
    assert 'sharing' not in browser.get('/api/companion/vault?vault_id='+identifier,headers=headers).json()
    assert browser.post('/api/companion/vault',headers=headers,json={'revision':1,'envelope':payload(identifier)}).status_code==422
    post(client,'/companions/revoke',{})
    assert browser.get('/api/companion/vault',headers=headers).status_code==401


def test_v4_schema_upgrade_preserves_vault_payloads_and_scopes_existing_tokens_to_personal(tmp_path):
    import json
    import sqlite3
    from backend.store import Store
    path=tmp_path/'old-v4.db'
    with sqlite3.connect(path) as c:
        c.execute('CREATE TABLE companions(token TEXT PRIMARY KEY,user TEXT NOT NULL,label TEXT,expires REAL NOT NULL,vault_id TEXT)')
        c.execute('INSERT INTO companions VALUES(?,?,?,?,?)',('fixture-hash','fixture-user','Old browser',9999999999,'fixture-personal-vault'))
        c.execute('CREATE TABLE team_vaults(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,owner TEXT NOT NULL,name TEXT NOT NULL,manifest TEXT NOT NULL,payload TEXT NOT NULL,epoch INTEGER NOT NULL,revision INTEGER NOT NULL,rotation_required INTEGER NOT NULL,created_at TEXT NOT NULL)')
        c.execute('INSERT INTO team_vaults VALUES(?,?,?,?,?,?,?,?,?,?)',('fixture-team','fixture-workspace','fixture-user','Old team','{}','opaque-preserved-ciphertext',3,7,0,'fixture-at'))
    store=Store(path)
    with store.connect() as c:
        token=c.execute('SELECT * FROM companions').fetchone();row=c.execute('SELECT * FROM team_vaults').fetchone()
        assert token['kind']=='personal' and token['workspace'] is None and token['vault_id']=='fixture-personal-vault'
        assert row['payload']=='opaque-preserved-ciphertext' and row['revision']==7 and row['epoch']==3
        assert json.loads(row['browser_policy'])['browser_enabled'] is True
