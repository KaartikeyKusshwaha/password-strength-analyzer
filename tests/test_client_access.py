import pytest
from fastapi.testclient import TestClient

from backend.store import Store, SCHEMA_VERSION
from test_platform import system, invited, post
from test_sharing import setup_identity, create, grant


def test_live_map_tracks_invites_revocation_and_rotation_without_payloads(system):
    app, client, _ = system
    other = invited(app, client)
    try:
        owner, member = setup_identity(client), setup_identity(other)
        vault = create(client, owner)
        customer = post(client, '/clients', {'name': 'Client Orchard'}).json()['id']
        assert post(client, f'/clients/{customer}/vaults', {'vault_id': vault}).json()['created']
        assert not post(client, f'/clients/{customer}/vaults', {'vault_id': vault}).json()['created']
        assert post(client, f'/team-vaults/{vault}/invite', grant(owner, member, vault)).status_code == 200
        mapped = client.get('/api/clients/access-map').json()
        assert len(mapped['grants']) == 2
        assert next(row for row in mapped['grants'] if row['person_id'] == member['id'])['state'] == 'invited'
        assert post(other, f'/team-vaults/{vault}/accept', {}).status_code == 200
        mapped = client.get('/api/clients/access-map').json()
        assert next(row for row in mapped['grants'] if row['person_id'] == member['id'])['state'] == 'accepted'
        assert post(client, f'/team-vaults/{vault}/revoke/{member["id"]}', {}).status_code == 200
        mapped = client.get('/api/clients/access-map').json()
        assert [row['person_id'] for row in mapped['grants']] == [owner['id']]
        assert mapped['systems'][0]['rotation_required'] == 1
        assert all(not {'payload', 'envelope', 'wrapped_key', 'password', 'token'}.intersection(row) for row in mapped['systems'] + mapped['grants'])
        assert 'does not establish website' in mapped['coverage']
        assert post(client, f'/clients/{customer}/vaults/{vault}/unlink', {}).json()['removed']
        assert client.get('/api/clients/access-map').json()['systems'] == []
        assert client.get(f'/api/team-vaults/{vault}').status_code == 200
        with app.state.store.connect() as c:
            events = Store.audit(c, client.get('/api/me').json()['workspace'])
            assert events['valid']
            assert sum(row['action'] == 'client.vault_linked' for row in events['events']) == 1
    finally:
        other.close()


def test_map_is_owner_only_and_workspace_scoped(system):
    app, client, _ = system
    other = invited(app, client)
    try:
        customer = post(client, '/clients', {'name': 'Client Private'}).json()['id']
        for reader in [other, TestClient(app)]:
            assert reader.get('/api/clients/access-map').status_code in {401, 403}
            assert post(reader, '/clients', {'name': 'Forbidden'}).status_code in {401, 403}
            assert post(reader, f'/clients/{customer}/vaults', {'vault_id': 'a'*24}).status_code in {401, 403}
        isolated = post(client, '/workspaces', {'name': 'Isolated'}).json()['id']
        post(client, f'/workspaces/{isolated}/switch', {})
        assert client.get('/api/clients/access-map').json()['clients'] == []
        assert post(client, f'/clients/{customer}/vaults', {'vault_id': 'a'*24}).status_code == 404
    finally:
        other.close()


def test_client_schema_upgrade_preserves_old_data_and_rejects_partial_layout(tmp_path):
    path = tmp_path/'migration.db'
    store = Store(path)
    with store.connect(write=True) as c:
        c.execute('DROP TABLE client_vaults')
        c.execute('DROP TABLE clients')
        c.execute('DELETE FROM schema_migrations WHERE version>=11')
        c.execute('DROP TABLE workflow_steps')
        c.execute('DROP TABLE workflows');c.execute('DROP TABLE access_grants');c.execute('DROP TABLE credential_exposures');c.execute('DROP TABLE handoff_records')
        c.execute("INSERT INTO workspaces VALUES('old','Unchanged',0)")
    for _ in range(2):
        with Store(path).connect() as c:
            assert c.execute('SELECT name FROM workspaces WHERE id=?', ('old',)).fetchone()[0] == 'Unchanged'
            assert c.execute('SELECT max(version) FROM schema_migrations').fetchone()[0] == SCHEMA_VERSION
    with store.connect(write=True) as c:
        c.execute('DROP TABLE client_vaults')
    with pytest.raises(ValueError, match='incomplete'):
        Store(path)
