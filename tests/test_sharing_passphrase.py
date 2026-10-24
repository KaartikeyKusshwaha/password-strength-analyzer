"""Identity wrapper changes require existing-key proof and preserve shared data."""
import hashlib

import pytest
from fastapi.testclient import TestClient

from backend.store import Store, canonical, now
from test_platform import system, invited, post
from test_sharing import setup_identity, sign, create, grant, b64


def rewrap(who, encrypted=None):
    encrypted=encrypted or {'version':1,'salt':b64(b'n'*16),'iv':b64(b'v'*12),'ciphertext':b64(b'new-opaque-encrypted-fixture-identity'*6)}
    previous=hashlib.sha256(canonical(who['body']['encrypted']).encode()).hexdigest()
    document={'action':'sharing.identity_rewrap.v1','user':who['id'],'fingerprint':who['fingerprint'],'previous_digest':previous,'encrypted':encrypted}
    return {'previous_digest':previous,'encrypted':encrypted,'signature':sign(who,document)}


def test_rewrap_preserves_keys_vaults_and_grants_revoking_only_own_shared_work(system):
    app,client,_=system
    owner=setup_identity(client);other=invited(app,client);recipient=setup_identity(other)
    identifier=create(client,owner)
    assert post(client,f'/team-vaults/{identifier}/invite',grant(owner,recipient,identifier,'editor')).status_code==200
    assert post(other,f'/team-vaults/{identifier}/accept',{}).status_code==200
    store=app.state.store
    workspace=client.get('/api/me').json()['workspace']
    second=post(client,'/workspaces',{'name':'Other client workspace'}).json()['id']
    with store.connect(write=True) as c:
        for token,user,kind,space in [('own-shared',owner['id'],'shared',workspace),('own-other-space',owner['id'],'shared',second),('own-personal',owner['id'],'personal',workspace),('other-shared',recipient['id'],'shared',workspace)]:
            c.execute('INSERT INTO companions(token,user,label,expires,vault_id,kind,workspace) VALUES(?,?,?,?,?,?,?)',(token,user,'fixture',9999999999,identifier,kind,space))
        for action,user,kind,space in [('active',owner['id'],'shared',workspace),('other-space',owner['id'],'shared',second),('personal',owner['id'],'personal',workspace),('other-user',recipient['id'],'shared',workspace)]:
            c.execute('INSERT INTO credential_actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(action,user,identifier,kind,space,'encrypted fixture',1,'running','{}','lease-hash','connection',9999999999,now(),9999999999))
        before=c.execute('SELECT public,fingerprint,created_at FROM sharing_identities WHERE user=?',(owner['id'],)).fetchone()[:]
        vault_before=c.execute('SELECT * FROM team_vaults').fetchall()[0][:]
        grants_before=[row[:] for row in c.execute('SELECT * FROM team_grants ORDER BY user')]
    change=rewrap(owner)
    response=post(client,'/sharing/identity/passphrase',change)
    assert response.status_code==200,response.text
    assert response.json()=={'fingerprint':owner['fingerprint'],'shared_connections_revoked':True}
    own=client.get('/api/sharing/identity').json()['identity']
    assert own['encrypted']==change['encrypted'] and own['public']==owner['public']
    assert other.get('/api/sharing/identity').json()['identity']['encrypted']==recipient['body']['encrypted']
    with store.connect() as c:
        assert c.execute('SELECT public,fingerprint,created_at FROM sharing_identities WHERE user=?',(owner['id'],)).fetchone()[:]==before
        assert c.execute('SELECT * FROM team_vaults').fetchall()[0][:]==vault_before
        assert [row[:] for row in c.execute('SELECT * FROM team_grants ORDER BY user')]==grants_before
        assert {r[0] for r in c.execute('SELECT token FROM companions')}=={'own-personal','other-shared'}
        for row in c.execute('SELECT * FROM credential_actions'):
            if row['id'] in {'active','other-space'}:
                assert row['status']=='cancelled' and row['lease_hash'] is None and row['lease_connection'] is None and row['lease_expires'] is None
            else:
                assert row['status']=='running' and row['lease_hash']=='lease-hash'
        for space in (workspace,second):
            audit=Store.audit(c,space)
            assert audit['valid'] and audit['events'][-1]['action']=='sharing.passphrase_changed'
    assert other.get('/api/team-vaults/'+identifier).status_code==200
    assert post(client,'/sharing/identity/passphrase',change).status_code==409


@pytest.mark.parametrize('mutation', ['ciphertext','signature','user','public','unchanged','salt','previous','plaintext'])
def test_invalid_rewrap_never_changes_identity_or_revokes_connections(system,mutation):
    app,client,_=system;who=setup_identity(client)
    change=rewrap(who)
    if mutation=='ciphertext':change['encrypted']['ciphertext']=b64(b'tampered fixture envelope'*8)
    elif mutation=='signature':change['signature']=b64(b'\x00'*64)
    elif mutation=='user':
        document={'action':'sharing.identity_rewrap.v1','user':'e'*24,'fingerprint':who['fingerprint'],'previous_digest':change['previous_digest'],'encrypted':change['encrypted']}
        change['signature']=sign(who,document)
    elif mutation=='public':change['public']=who['public']
    elif mutation=='plaintext':change['passphrase']='never accept a plaintext passphrase'
    elif mutation=='unchanged':change=rewrap(who,who['body']['encrypted'])
    elif mutation=='salt':change=rewrap(who,{**change['encrypted'],'salt':who['body']['encrypted']['salt']})
    else:change['previous_digest']='0'*64
    with app.state.store.connect(write=True) as c:
        c.execute('INSERT INTO companions(token,user,label,expires,kind) VALUES(?,?,?,?,?)',('preserve-token',who['id'],'fixture',9999999999,'shared'))
    response=post(client,'/sharing/identity/passphrase',change)
    assert response.status_code in {409,422},response.text
    assert client.get('/api/sharing/identity').json()['identity']['encrypted']==who['body']['encrypted']
    with app.state.store.connect() as c:
        assert c.execute('SELECT COUNT(*) FROM companions').fetchone()[0]==1
        assert not c.execute("SELECT 1 FROM audit WHERE action='sharing.passphrase_changed'").fetchone()


def test_existing_key_proof_is_user_scoped_and_viewers_can_maintain_their_identity(system):
    app,client,_=system;who=setup_identity(client)
    viewer=invited(app,client,'viewer');reader=setup_identity(viewer)
    change=rewrap(who)
    assert post(viewer,'/sharing/identity/passphrase',change).status_code==422
    assert post(viewer,'/sharing/identity/passphrase',rewrap(reader)).status_code==200
    assert client.get('/api/sharing/identity').json()['identity']['encrypted']==who['body']['encrypted']
    assert TestClient(app).post('/api/sharing/identity/passphrase',json=change).status_code==401
    assert client.post('/api/sharing/identity/passphrase',json=change).status_code==403


def test_competing_signed_changes_cannot_overwrite_the_accepted_wrapper(system):
    _,client,_=system;who=setup_identity(client)
    first=rewrap(who)
    second=rewrap(who,{**first['encrypted'],'salt':b64(b'z'*16),'iv':b64(b'y'*12)})
    assert post(client,'/sharing/identity/passphrase',first).status_code==200
    assert post(client,'/sharing/identity/passphrase',second).status_code==409
    assert client.get('/api/sharing/identity').json()['identity']['encrypted']==first['encrypted']
