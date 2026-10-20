"""Scoped, paginated service events. Never reads a vault or action envelope."""
import json
from typing import Literal

from fastapi import Depends, HTTPException, Path, Query

from .store import Store, now
from .companion_status import forget as forget_connection_status

PERSONAL_EVENTS = (
    'vault.created', 'vault.properties_updated', 'vault.default_changed',
    'vault.archived', 'vault.restored', 'vault.initialized', 'vault.saved',
    'vault.browser_saved', 'vault.protection_changed', 'vault.companion_connected',
    'vault.companions_revoked', 'vault.recovery_restored',
)
TEAM_EVENTS = (
    'team_vault.created', 'team_vault.browser_policy_updated',
    'team_vault.invitation_accepted', 'team_vault.invited', 'team_vault.saved',
    'team_vault.access_revoked', 'team_vault.key_rotated', 'team_vault.browser_saved',
    'team_vault.companion_connected', 'team_vault.companions_revoked',
    'team_vault.recovery_restored',
    'team_vault.ownership_proposed', 'team_vault.ownership_cancelled',
    'team_vault.ownership_declined', 'team_vault.ownership_transferred',
    'team_vault.ownership_invalidated',
)
ACTION_EVENTS = tuple('credential_action.' + state for state in (
    'approved', 'claimed', 'resumed', 'expired', 'interrupted', 'cancelled',
    'prepared', 'needs_attention', 'confirmed_by_user', 'discarded',
))


def record_connection_revocations(c, connections, actor):
    """Call in the same transaction as revoking these scoped connections."""
    seen = set()
    for row in connections:
        forget_connection_status(c,row)
        # Stop only work leased to this connection. Preserve encrypted plans and
        # per-item progress; another browser needs an explicit resume.
        actions=c.execute("SELECT id,workspace,user FROM credential_actions WHERE user=? AND lease_connection=? AND status IN ('running','awaiting_confirmation')",(row['user'],row['token'])).fetchall()
        c.execute("UPDATE credential_actions SET status='interrupted',lease_hash=NULL,lease_connection=NULL,lease_expires=NULL WHERE user=? AND lease_connection=? AND status IN ('running','awaiting_confirmation')",(row['user'],row['token']))
        for action in actions:
            Store.event(c,action['workspace'] or 'personal:'+action['user'],actor,'credential_action.interrupted',action['id'])
        if not row['vault_id']:
            continue  # Legacy unscoped connections cannot be attributed honestly.
        key = (row['kind'], row['vault_id'], row['user'], row['workspace'])
        if key in seen:
            continue
        seen.add(key)
        shared = row['kind'] == 'shared'
        scope = row['workspace'] if shared else 'personal:' + row['user']
        if scope:
            Store.event(c, scope, actor, ('team_vault.' if shared else 'vault.') + 'companions_revoked', row['vault_id'])


def record_action_cancellations(c, actions, actor):
    for row in actions:
        Store.event(c, row['workspace'] or 'personal:'+row['user'], actor, 'credential_action.cancelled', row['id'])


def invalidate_ownership(c,workspace,vault,actor,reason):
    # A policy changed and changed back must not revive an old signed approval.
    rows=c.execute("SELECT data FROM entities WHERE workspace=? AND kind='ownership_transfers' AND json_extract(data,'$.document.vault_id')=? AND json_extract(data,'$.status')='pending'",(workspace,vault)).fetchall()
    for row in rows:
        value=json.loads(row[0]);value.update(status='stale',reason=reason,finished_at=now())
        Store.put(c,workspace,'ownership_transfers',value)
        Store.event(c,workspace,actor,'team_vault.ownership_invalidated',vault+':'+value['id'])


def allowed(actions, prefix, params):
    names = []
    for index, value in enumerate(actions):
        name = prefix + str(index)
        params[name] = value
        names.append(':' + name)
    return '(' + ','.join(names) + ')'


def register(app, store, auth, throttle):
    @app.get('/api/vault-activity/{kind}/{identifier}')
    def activity(kind: Literal['personal', 'shared'], identifier: str = Path(pattern=r'^[a-f0-9]{24}$'),
                 before: int | None = Query(default=None, ge=1, le=9223372036854775807),
                 limit: int = Query(default=50, ge=1, le=100), session=Depends(auth)):
        throttle('vault-activity:' + session['user'], 120)
        with store.connect() as c:
            c.execute('BEGIN')
            params = {'user': session['user'], 'vault': identifier, 'workspace': session['workspace'],
                      'personal': 'personal:' + session['user'], 'limit': limit + 1}
            if kind == 'personal':
                row = c.execute('SELECT id FROM vault_spaces WHERE id=? AND user=?', (identifier, session['user'])).fetchone()
                direct = 'a.action IN ' + allowed(PERSONAL_EVENTS, 'v', params) + ' AND a.target=:vault'
                # Retain historical metadata events written under a workspace,
                # but only for this owner and exactly this personal vault.
                scope = '(a.workspace=:personal OR a.actor=:user)'
                action_scope = "j.kind='personal' AND j.user=:user AND a.workspace=:personal"
            else:
                row = c.execute('SELECT v.id FROM team_vaults v JOIN team_grants g ON g.vault=v.id JOIN members m ON m.workspace=v.workspace AND m.user=g.user WHERE v.id=? AND v.workspace=? AND g.user=? AND g.accepted=1', (identifier, session['workspace'], session['user'])).fetchone()
                direct = 'a.action IN ' + allowed(TEAM_EVENTS, 'v', params) + " AND (a.target=:vault OR substr(a.target,1,length(:vault)+1)=:vault||':')"
                scope = 'a.workspace=:workspace'
                action_scope = "j.kind='shared' AND j.workspace=:workspace AND a.workspace=:workspace"
            if not row:
                raise HTTPException(404, 'Vault activity not found or access removed')
            action_events = allowed(ACTION_EVENTS, 'j', params)
            related = f"a.action IN {action_events} AND EXISTS (SELECT 1 FROM credential_actions j WHERE j.vault_id=:vault AND {action_scope} AND (a.target=j.id OR substr(a.target,1,length(j.id)+1)=j.id||':'))"
            where = f'{scope} AND (({direct}) OR ({related}))'
            if before is not None:
                where += ' AND a.seq<:before'
                params['before'] = before
            # Keyset pagination: concurrent new events do not shift older pages.
            rows = c.execute(f'SELECT a.seq,a.at,a.actor,a.action FROM audit a WHERE {where} ORDER BY a.seq DESC LIMIT :limit', params).fetchall()
            labels = {r['id']: r['email'] for r in c.execute('SELECT u.id,u.email FROM users u JOIN members m ON m.user=u.id WHERE m.workspace=?', (session['workspace'],))} if kind == 'shared' else {}
            events = [{'id': r['seq'], 'at': r['at'], 'action': r['action'],
                       'actor': r['actor'], 'actor_label': 'You' if r['actor'] == session['user'] else 'System' if isinstance(r['actor'],str) and r['actor'].startswith('system:') else labels.get(r['actor'], 'Former or unavailable member')}
                      for r in rows[:limit]]
            return {'events': events, 'next_before': events[-1]['id'] if len(rows) > limit else None,
                    'source': 'service_record', 'independently_verified': False}
