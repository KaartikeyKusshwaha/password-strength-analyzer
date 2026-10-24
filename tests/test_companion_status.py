import json
from contextlib import contextmanager
import pytest
from zipfile import ZipFile

from fastapi.testclient import TestClient

from backend import companion_status as status
from backend.security import digest
from test_platform import PASSWORD, invited, post, system
from test_companions import envelope
from test_sharing import setup_identity,create,payload


def connect(client):
    result=post(client,'/companions',{'label':'Acceptance browser','password':PASSWORD})
    assert result.status_code==200,result.text
    return result.json()['token']


def headers(token,version='0.12.7'):
    return {'Authorization':'Bearer '+token,'Origin':'chrome-extension://'+'a'*32,status.HEADER:version}


def test_records_successful_bearer_contact_without_exposing_token_or_vault_contents(system):
    app,client,_=system
    token=connect(client)
    before=client.get('/api/companions').json()['connections'][0]
    assert before['last_contact'] is None and before['reported_version'] is None
    extension=TestClient(app)
    assert extension.get('/api/companion/vault',headers=headers(token)).status_code==200
    result=client.get('/api/companions').json()
    value=result['connections'][0]
    assert value['reported_version']=='0.12.7' and value['last_contact']>0
    assert set(value)=={'id','label','kind','expires','last_contact','reported_version'}
    assert token not in json.dumps(result) and digest(token) not in json.dumps(result)
    assert extension.get('/api/companions',headers=headers(token)).status_code==401
    assert 'companion_status' not in client.get('/api/workspace').text
    other=invited(app,client)
    assert other.get('/api/companions').json()['connections']==[]


def test_invalid_tokens_and_untrusted_origins_cannot_create_reports(system):
    app,client,_=system
    token=connect(client);extension=TestClient(app)
    assert extension.get('/api/companion/vault',headers=headers('wrong-token')).status_code==401
    # A denied POST must not acquire a contact record, even with a valid bearer.
    assert extension.post('/api/companion/vault',headers={**headers(token),'Origin':'https://hostile.invalid'},json={}).status_code==403
    assert client.get('/api/companions').json()['connections'][0]['last_contact'] is None
    assert extension.options('/api/companion/vault',headers={'Origin':headers(token)['Origin'],'Access-Control-Request-Method':'GET','Access-Control-Request-Headers':'authorization,x-sentinel-companion-version'}).headers['access-control-allow-headers'].endswith('X-Sentinel-Companion-Version')


def test_old_or_malformed_version_reports_do_not_break_legacy_connections(system):
    app,client,_=system
    token=connect(client);extension=TestClient(app)
    for version in ['', '0.12.7<script>', '001.2.3', '0.12.7-credentials', '9'*100]:
        assert extension.get('/api/companion/vault',headers=headers(token,version)).status_code==200
        value=client.get('/api/companions').json()['connections'][0]
        assert value['last_contact']>0 and value['reported_version'] is None
    assert extension.get('/api/companion/vault',headers={'Authorization':'Bearer '+token}).status_code==200


def test_reports_coalesce_and_revocation_clears_them_without_resurrection(system):
    app,client,_=system
    token=connect(client);extension=TestClient(app)
    extension.get('/api/companion/vault',headers=headers(token))
    with app.state.store.connect() as c:
        connection=dict(c.execute('SELECT * FROM companions WHERE token=?',(digest(token),)).fetchone())
    first=client.get('/api/companions').json()['connections'][0]['last_contact']
    status.record_read(app.state.store,connection,'0.12.7',first+10)
    assert client.get('/api/companions').json()['connections'][0]['last_contact']==first
    status.record_read(app.state.store,connection,'0.12.6',first+11)
    assert client.get('/api/companions').json()['connections'][0]['reported_version']=='0.12.6'
    assert post(client,'/companions/revoke',{}).status_code==200
    status.record_read(app.state.store,connection,'0.12.7',first+12)
    assert client.get('/api/companions').json()['connections']==[]
    with app.state.store.connect() as c:
        assert c.execute("SELECT count(*) FROM entities WHERE kind='companion_status'").fetchone()[0]==0
    assert extension.get('/api/companion/vault',headers=headers(token)).status_code==401


def test_packaged_version_uses_the_archive_and_rejects_missing_or_oversized_metadata(tmp_path):
    package=tmp_path/'package.zip'
    assert status.packaged_version(package) is None
    with ZipFile(package,'w') as archive:archive.writestr('manifest.json',json.dumps({'version':'0.12.7'}))
    assert status.packaged_version(package)=='0.12.7'
    with ZipFile(package,'w') as archive:archive.writestr('manifest.json',' '*8193)
    assert status.packaged_version(package) is None
    with ZipFile(package,'w') as archive:archive.writestr('manifest.json','[]')
    assert status.packaged_version(package) is None


def test_single_revocation_is_account_scoped_csrf_protected_and_preserves_other_tokens(system):
    app,client,_=system
    first=connect(client)
    first_id=client.get('/api/companions').json()['connections'][0]['id']
    second=connect(client);extension=TestClient(app)
    assert extension.get('/api/companion/vault',headers=headers(first)).status_code==200
    assert extension.get('/api/companion/vault',headers=headers(second)).status_code==200
    other=invited(app,client)
    assert post(other,'/companions/'+first_id+'/revoke',{}).status_code==404
    assert client.post('/api/companions/'+first_id+'/revoke',json={}).status_code==403
    assert extension.post('/api/companions/'+first_id+'/revoke',headers=headers(first),json={}).status_code==403
    assert extension.post('/api/companions/'+first_id+'/revoke',headers={'Authorization':'Bearer '+first},json={}).status_code==401
    assert post(client,'/companions/not-an-id/revoke',{}).status_code==404
    with app.state.store.connect() as c:
        before=[tuple(row) for row in c.execute('SELECT * FROM vault_spaces ORDER BY id')]
    assert post(client,'/companions/'+first_id+'/revoke',{}).status_code==200
    assert extension.get('/api/companion/vault',headers=headers(first)).status_code==401
    assert extension.get('/api/companion/vault',headers=headers(second)).status_code==200
    assert len(client.get('/api/companions').json()['connections'])==1
    assert post(client,'/companions/'+first_id+'/revoke',{}).status_code==404
    with app.state.store.connect() as c:
        assert [tuple(row) for row in c.execute('SELECT * FROM vault_spaces ORDER BY id')]==before
        assert c.execute("SELECT count(*) FROM entities WHERE kind='companion_status'").fetchone()[0]==1


@pytest.mark.parametrize('kind',['personal','shared'])
@pytest.mark.parametrize('write',[False,True])
def test_actual_vault_routes_recheck_revocation_after_initial_bearer_lookup(system,monkeypatch,kind,write):
    app,client,_=system
    if kind=='personal':
        vault=post(client,'/vaults',{'name':'Race fixture'}).json()['id']
        assert post(client,'/vault?vault_id='+vault,{'revision':0,'envelope':envelope()}).status_code==200
        endpoint='/api/vault?vault_id='+vault
    else:
        vault=create(client,setup_identity(client));endpoint='/api/team-vaults/'+vault
    paired=post(client,'/companions',{'kind':kind,'vault_id':vault,'label':'Race browser','password':PASSWORD})
    assert paired.status_code==200
    token=paired.json()['token'];browser=TestClient(app)
    before=client.get(endpoint).json();original=app.state.store.connect;armed=True
    @contextmanager
    def revoke_after_lookup(write=False):
        nonlocal armed
        with original(write=write) as c:yield c
        if not write and armed:
            armed=False
            # The auth function has its row; revoke before the vault-use transaction.
            with original(write=True) as c:c.execute('DELETE FROM companions WHERE token=?',(digest(token),))
    monkeypatch.setattr(app.state.store,'connect',revoke_after_lookup)
    if write:
        response=browser.post('/api/companion/vault',headers=headers(token),json={'revision':before['revision'],'envelope':envelope() if kind=='personal' else payload(vault)})
    else:response=browser.get('/api/companion/vault',headers=headers(token))
    assert response.status_code==401,response.text
    assert armed is False
    assert client.get(endpoint).json()==before
    assert 'ciphertext' not in response.text
