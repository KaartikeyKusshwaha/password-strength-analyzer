"""Owner-only access metadata. Shared membership is not external-account proof."""
from fastapi import Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .store import Store, now, uid


class ClientCreate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    name: str = Field(min_length=2, max_length=100)


class VaultLink(BaseModel):
    model_config = ConfigDict(extra='forbid')
    vault_id: str = Field(pattern=r'^[a-f0-9]{24}$')


def snapshot(store, workspace):
    with store.connect() as c:
        clients = [dict(row) for row in c.execute('SELECT id,name FROM clients WHERE workspace=? ORDER BY name,id', (workspace,))]
        systems = [dict(row) for row in c.execute('SELECT l.client,v.id,v.name,v.rotation_required,v.epoch FROM client_vaults l JOIN clients p ON p.id=l.client AND p.workspace=l.workspace JOIN team_vaults v ON v.id=l.vault AND v.workspace=l.workspace WHERE l.workspace=? ORDER BY p.name,v.name,v.id', (workspace,))]
        grants = [dict(row) for row in c.execute('SELECT l.client,g.user AS person_id,u.email,v.id AS system_id,g.role,g.accepted FROM client_vaults l JOIN clients p ON p.id=l.client AND p.workspace=l.workspace JOIN team_vaults v ON v.id=l.vault AND v.workspace=l.workspace JOIN team_grants g ON g.vault=v.id JOIN members m ON m.user=g.user AND m.workspace=l.workspace JOIN users u ON u.id=g.user WHERE l.workspace=? ORDER BY l.client,u.email,v.id', (workspace,))]
        for row in grants:
            row['source'] = 'shared_vault_membership'
            row['state'] = 'accepted' if row.pop('accepted') else 'invited'
        for row in systems:
            row['kind'] = 'shared_vault'
        available = [dict(row) for row in c.execute('SELECT id,name FROM team_vaults WHERE workspace=? ORDER BY name,id', (workspace,))]
        people=[dict(row) for row in c.execute('SELECT u.id,u.email,m.role FROM members m JOIN users u ON u.id=m.user WHERE m.workspace=? ORDER BY u.email,u.id',(workspace,))]
        reported=[dict(row) for row in c.execute('SELECT a.*,u.email FROM access_grants a JOIN users u ON u.id=a.person WHERE a.workspace=? ORDER BY a.client,a.domain,a.account_label,a.id',(workspace,))]
        known=set()
        for row in reported:
            if row['state']=='retired':continue
            key=(row['client'],row['domain'])
            if key not in known:
                systems.append({'client':row['client'],'id':'account:'+row['domain'],'name':row['domain'],'kind':'reported_account','rotation_required':False,'epoch':None});known.add(key)
            grants.append({'id':row['id'],'client':row['client'],'person_id':row['person'],'email':row['email'],'system_id':'account:'+row['domain'],'role':row['role'],'source':row['source'],'state':row['state'],'account_label':row['account_label'],'updated_at':row['updated_at']})

    return {'clients': clients, 'systems': systems, 'grants': grants, 'available_vaults': available,'people':people,'retired_records':[row for row in reported if row['state']=='retired'],
            'coverage': 'Live shared-vault memberships, manual reports and opt-in login-attempt observations. Invitations and reported activity are not verified external access. This does not establish website account ownership, active sessions, MFA, device compliance or completed offboarding.'}


def register(app, store, auth, throttle):
    def owner(session):
        if session['role'] != 'owner':
            raise HTTPException(403, 'Workspace owner access required for the client access map.')

    def client(c, workspace, identifier):
        row = c.execute('SELECT * FROM clients WHERE id=? AND workspace=?', (identifier, workspace)).fetchone()
        if not row:
            raise HTTPException(404, 'Client not found.')
        return row

    @app.get('/api/clients/access-map')
    def access_map(session=Depends(auth)):
        owner(session)
        return snapshot(store, session['workspace'])

    @app.post('/api/clients')
    def create(body: ClientCreate, session=Depends(auth)):
        owner(session)
        throttle('client-create:' + session['workspace'], 30)
        with store.connect(write=True) as c:
            if c.execute('SELECT count(*) FROM clients WHERE workspace=?', (session['workspace'],)).fetchone()[0] >= 500:
                raise HTTPException(409, 'Client limit reached.')
            identifier = uid()
            c.execute('INSERT INTO clients VALUES(?,?,?,?)', (identifier, session['workspace'], body.name, now()))
            Store.event(c, session['workspace'], session['user'], 'client.created', identifier)
        return {'id': identifier, 'name': body.name}

    @app.post('/api/clients/{identifier}/vaults')
    def link(identifier: str, body: VaultLink, session=Depends(auth)):
        owner(session)
        with store.connect(write=True) as c:
            client(c, session['workspace'], identifier)
            if not c.execute('SELECT 1 FROM team_vaults WHERE id=? AND workspace=?', (body.vault_id, session['workspace'])).fetchone():
                raise HTTPException(404, 'Shared vault not found in this workspace.')
            changed = c.execute('INSERT OR IGNORE INTO client_vaults VALUES(?,?,?)', (identifier, session['workspace'], body.vault_id)).rowcount
            if changed:
                Store.event(c, session['workspace'], session['user'], 'client.vault_linked', identifier + ':' + body.vault_id)
        return {'ok': True, 'created': bool(changed)}

    @app.post('/api/clients/{identifier}/vaults/{vault}/unlink')
    def unlink(identifier: str, vault: str, session=Depends(auth)):
        owner(session)
        with store.connect(write=True) as c:
            client(c, session['workspace'], identifier)
            changed = c.execute('DELETE FROM client_vaults WHERE client=? AND workspace=? AND vault=?', (identifier, session['workspace'], vault)).rowcount
            if changed:
                Store.event(c, session['workspace'], session['user'], 'client.vault_unlinked', identifier + ':' + vault)
        return {'ok': True, 'removed': bool(changed), 'note': 'Metadata link only. Vault access was not revoked.'}
