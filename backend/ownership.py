"""Mutually approved shared-vault ownership transfer; no private keys on server."""
import hashlib
import json
import time
from typing import Literal

from fastapi import Depends, HTTPException
from pydantic import Field

from .sharing import Body, Grant, TeamPayload, verify
from .store import Store, canonical, now
from .vault_activity import record_action_cancellations, record_connection_revocations


class ProposalDocument(Body):
    action: Literal['team_vault.ownership.v1']
    version: Literal[1]
    id: str = Field(pattern=r'^[a-f0-9]{24}$')
    vault_id: str = Field(pattern=r'^[a-f0-9]{24}$')
    workspace: str = Field(pattern=r'^[a-f0-9]{24}$')
    owner: str = Field(pattern=r'^[a-f0-9]{24}$')
    recipient: str = Field(pattern=r'^[a-f0-9]{24}$')
    owner_fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')
    recipient_fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')
    state_digest: str = Field(pattern=r'^[a-f0-9]{64}$')
    revision: int = Field(ge=1)
    epoch: int = Field(ge=1,lt=1000000)
    former_owner_role: Literal['removed','viewer','editor','admin']
    expires_at: int


class Proposal(Body):
    document: ProposalDocument
    signature: str = Field(min_length=88,max_length=88)


class Acceptance(Body):
    proposal_id: str = Field(pattern=r'^[a-f0-9]{24}$')
    revision: int = Field(ge=1)
    manifest_signature: str = Field(min_length=88,max_length=88)
    payload: TeamPayload
    grants: list[Grant] = Field(min_length=1,max_length=20)
    signature: str = Field(min_length=88,max_length=88)


def require(condition,message,code=409):
    if not condition:
        raise HTTPException(code,message)


def state_digest(c,vault):
    owner=c.execute('SELECT fingerprint FROM sharing_identities WHERE user=?',(vault['owner'],)).fetchone()
    require(owner,'Vault owner identity is unavailable')
    grants=[{'user_id':r['user'],'role':r['role'],'accepted':bool(r['accepted']),'envelope':json.loads(r['envelope'])}
            for r in c.execute('SELECT * FROM team_grants WHERE vault=? ORDER BY user',(vault['id'],))]
    value={'id':vault['id'],'workspace':vault['workspace'],'owner':vault['owner'],'owner_fingerprint':owner['fingerprint'],
           'epoch':vault['epoch'],'revision':vault['revision'],'rotation_required':bool(vault['rotation_required']),
           'browser_policy':json.loads(vault['browser_policy']),'manifest':json.loads(vault['manifest']),
           'payload':json.loads(vault['payload']),'grants':grants}
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def pending(c,workspace,vault):
    return [json.loads(r[0]) for r in c.execute("SELECT data FROM entities WHERE workspace=? AND kind='ownership_transfers' AND json_extract(data,'$.document.vault_id')=? AND json_extract(data,'$.status')='pending' ORDER BY rowid DESC",(workspace,vault))]


def cancel_identity_proposals(c,user):
    rows=c.execute("SELECT workspace,data FROM entities WHERE kind='ownership_transfers' AND json_extract(data,'$.status')='pending' AND (json_extract(data,'$.document.owner')=? OR json_extract(data,'$.document.recipient')=?)",(user,user)).fetchall()
    for row in rows:
        value=json.loads(row['data']);value.update(status='cancelled',finished_at=now(),reason='sharing_protection_changed')
        Store.put(c,row['workspace'],'ownership_transfers',value)
        Store.event(c,row['workspace'],user,'team_vault.ownership_cancelled',value['document']['vault_id']+':'+value['id'])


def incoming(c,workspace,user):
    rows=c.execute("SELECT e.id,e.data,v.id AS vault_id,v.name FROM entities e JOIN team_vaults v ON v.id=json_extract(e.data,'$.document.vault_id') AND v.workspace=e.workspace JOIN team_grants g ON g.vault=v.id AND g.user=? AND g.accepted=1 WHERE e.workspace=? AND e.kind='ownership_transfers' AND json_extract(e.data,'$.status')='pending' AND json_extract(e.data,'$.document.recipient')=? AND json_extract(e.data,'$.document.expires_at')>? ORDER BY e.rowid DESC LIMIT 20",(user,workspace,user,time.time())).fetchall()
    return [{'id':r['id'],'vault_id':r['vault_id'],'vault_name':r['name'],'expires_at':json.loads(r['data'])['document']['expires_at']} for r in rows]


def register(app,store,auth,writable,throttle,team,identity,validate_grant):
    def recipient(c,vault,user):
        row=c.execute('SELECT g.role,g.accepted,m.role AS member_role,i.fingerprint FROM team_grants g JOIN members m ON m.user=g.user AND m.workspace=? JOIN sharing_identities i ON i.user=g.user WHERE g.vault=? AND g.user=?',(vault['workspace'],vault['id'],user)).fetchone()
        require(row and row['accepted'] and row['member_role']!='viewer','Choose an accepted teammate whose workspace role permits ownership',422)
        return row

    def current_status(c,value,vault):
        if value['status']!='pending':return value['status']
        if value['document']['expires_at']<=time.time():return 'expired'
        if value['document']['state_digest']!=state_digest(c,vault):return 'stale'
        return 'pending'

    @app.get('/api/team-vaults/{identifier}/ownership')
    def get_proposal(identifier: str,session=Depends(auth)):
        with store.connect() as c:
            c.execute('BEGIN')
            vault=team(c,session,identifier)
            row=c.execute("SELECT data FROM entities WHERE workspace=? AND kind='ownership_transfers' AND json_extract(data,'$.document.vault_id')=? ORDER BY rowid DESC LIMIT 1",(session['workspace'],identifier)).fetchone()
            value=json.loads(row[0]) if row else None
            if value and session['user'] not in (value['document']['owner'],value['document']['recipient']):value=None
            return {'proposal':{**value,'status':current_status(c,value,vault)} if value else None}

    @app.post('/api/team-vaults/{identifier}/ownership')
    def propose(identifier: str,body: Proposal,session=Depends(auth)):
        writable(session);throttle('ownership:'+session['user'],20)
        document=body.document.model_dump()
        with store.connect(write=True) as c:
            vault=team(c,session,identifier)
            require(vault['owner']==session['user'] and vault['role']=='owner','Only the current vault owner may propose a transfer',403)
            require(not vault['rotation_required'],'Rotate the vault key before transferring ownership')
            require(document['owner']==session['user'] and document['vault_id']==identifier and document['workspace']==session['workspace'],'Ownership proposal scope mismatch',422)
            require(document['recipient']!=vault['owner'],'Choose a different owner',422)
            target=recipient(c,vault,document['recipient']);owner=identity(c,vault['owner'])
            require(document['owner_fingerprint']==owner['fingerprint'] and document['recipient_fingerprint']==target['fingerprint'],'Verify current identity fingerprints again')
            require(document['revision']==vault['revision'] and document['epoch']==vault['epoch'] and document['state_digest']==state_digest(c,vault),'Vault contents or access changed; prepare a new proposal')
            require(time.time()+60<=document['expires_at']<=time.time()+1800,'Approve a transfer expiring within 30 minutes',422)
            verify(json.loads(owner['public']),document,body.signature)
            require(not c.execute('SELECT 1 FROM entities WHERE id=?',(document['id'],)).fetchone(),'Proposal id already exists')
            for previous in pending(c,session['workspace'],identifier):
                status=current_status(c,previous,vault)
                require(status!='pending','Cancel the existing proposal before creating another')
                previous.update(status=status,finished_at=now());Store.put(c,session['workspace'],'ownership_transfers',previous)
            value={'id':document['id'],'document':document,'signature':body.signature,'status':'pending','created_at':now()}
            Store.put(c,session['workspace'],'ownership_transfers',value)
            Store.event(c,session['workspace'],session['user'],'team_vault.ownership_proposed',identifier+':'+value['id'])
            # Keep pending proposals plus at most 100 terminal receipts per workspace.
            terminal=c.execute("SELECT id FROM entities WHERE workspace=? AND kind='ownership_transfers' AND json_extract(data,'$.status')!='pending' ORDER BY rowid DESC LIMIT -1 OFFSET 100",(session['workspace'],)).fetchall()
            for row in terminal:c.execute('DELETE FROM entities WHERE id=?',(row['id'],))
        return {'proposal':value}

    @app.post('/api/team-vaults/{identifier}/ownership/{proposal_id}/cancel')
    def cancel(identifier: str,proposal_id: str,session=Depends(auth)):
        with store.connect(write=True) as c:
            team(c,session,identifier)
            value=Store.get(c,session['workspace'],'ownership_transfers',proposal_id)
            require(value and value['document']['vault_id']==identifier,'Proposal not found',404)
            document=value['document'];require(session['user'] in (document['owner'],document['recipient']),'Only the proposing owner or intended recipient may cancel',403)
            require(value['status']=='pending','This proposal has already stopped')
            status='cancelled' if session['user']==document['owner'] else 'declined'
            value.update(status=status,finished_at=now());Store.put(c,session['workspace'],'ownership_transfers',value)
            Store.event(c,session['workspace'],session['user'],'team_vault.ownership_'+status,identifier+':'+proposal_id)
        return {'status':status}

    @app.post('/api/team-vaults/{identifier}/ownership/accept')
    def accept(identifier: str,body: Acceptance,session=Depends(auth)):
        writable(session);throttle('ownership-accept:'+session['user'],20)
        with store.connect(write=True) as c:
            vault=team(c,session,identifier)
            value=Store.get(c,session['workspace'],'ownership_transfers',body.proposal_id)
            require(value and value['document']['vault_id']==identifier,'Proposal not found',404)
            document=value['document']
            require(document['recipient']==session['user'],'Only the intended new owner may accept',403)
            require(current_status(c,value,vault)=='pending','Proposal expired, changed or stopped; ask the current owner for a new proposal')
            require(not vault['rotation_required'] and document['owner']==vault['owner'],'Vault ownership or key state changed')
            target=recipient(c,vault,session['user']);old_owner=identity(c,vault['owner']);new_owner=identity(c,session['user'])
            require(document['owner_fingerprint']==old_owner['fingerprint'] and document['recipient_fingerprint']==target['fingerprint'],'Ownership identity changed')
            verify(json.loads(old_owner['public']),document,value['signature'])
            require(body.revision==vault['revision'] and body.payload.context==identifier and body.payload.epoch==vault['epoch']+1,'Transfer requires the unchanged revision and next key epoch',422)
            received=body.model_dump();consent={'action':'team_vault.ownership_accept.v1','state_digest':document['state_digest'],**{k:v for k,v in received.items() if k!='signature'}}
            verify(json.loads(new_owner['public']),consent,body.signature)
            manifest={'id':identifier,'workspace':vault['workspace'],'owner':session['user'],'owner_fingerprint':new_owner['fingerprint']}
            verify(json.loads(new_owner['public']),manifest,body.manifest_signature)
            existing={r['user']:dict(r) for r in c.execute('SELECT * FROM team_grants WHERE vault=?',(identifier,))}
            expected={user:row['role'] for user,row in existing.items()}
            if document['former_owner_role']=='removed':expected.pop(vault['owner'])
            else:expected[vault['owner']]=document['former_owner_role']
            expected[session['user']]='owner'
            require(len(body.grants)==len(expected) and {g.recipient for g in body.grants}==set(expected),'Transfer must cover exactly the approved members',422)
            output=[];next_vault={**vault,'owner':session['user'],'epoch':vault['epoch']+1}
            for grant in body.grants:
                require(grant.role==expected[grant.recipient],'Transfer cannot silently change another member role',422)
                output.append((grant.recipient,validate_grant(c,grant,next_vault,session['user'],grant.recipient==session['user'])))
            for user,envelope in output:
                c.execute('UPDATE team_grants SET role=?,envelope=? WHERE vault=? AND user=?',(expected[user],canonical(envelope),identifier,user))
            if document['former_owner_role']=='removed':c.execute('DELETE FROM team_grants WHERE vault=? AND user=?',(identifier,vault['owner']))
            c.execute('UPDATE team_vaults SET owner=?,manifest=?,payload=?,epoch=epoch+1,revision=revision+1 WHERE id=?',(session['user'],canonical({'document':manifest,'signature':body.manifest_signature}),canonical(body.payload.model_dump()),identifier))
            record_connection_revocations(c,c.execute("SELECT * FROM companions WHERE kind='shared' AND vault_id=?",(identifier,)).fetchall(),session['user'])
            c.execute("DELETE FROM companions WHERE kind='shared' AND vault_id=?",(identifier,))
            record_action_cancellations(c,c.execute("SELECT id,workspace,user FROM credential_actions WHERE kind='shared' AND vault_id=? AND status NOT IN ('complete','cancelled','expired')",(identifier,)).fetchall(),session['user'])
            c.execute("UPDATE credential_actions SET status='cancelled',lease_hash=NULL,lease_connection=NULL,lease_expires=NULL WHERE kind='shared' AND vault_id=? AND status NOT IN ('complete','cancelled','expired')",(identifier,))
            value.update(status='accepted',finished_at=now(),acceptance_signature=body.signature,new_epoch=vault['epoch']+1)
            Store.put(c,session['workspace'],'ownership_transfers',value)
            Store.event(c,session['workspace'],session['user'],'team_vault.ownership_transferred',identifier+':'+body.proposal_id)
        return {'owner':session['user'],'epoch':vault['epoch']+1,'revision':vault['revision']+1,'shared_connections_revoked':True}
