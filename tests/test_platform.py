import base64
import json
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.app import Settings, create_app
from backend import agents, scanner
from backend.security import digest, totp
from backend.store import Store, uid

PASSWORD = "Fixture-Only!harbor-river-orbit-79"


def post(client, path, body, **kwargs):
    me = client.get('/api/me')
    headers = {"X-CSRF-Token": me.json()["csrf"]} if me.status_code == 200 else {}
    return client.post('/api' + path, json=body, headers=headers, **kwargs)


@pytest.fixture
def system(tmp_path):
    # Legacy feature fixtures deliberately omit MFA. Default production policy
    # and its rollout/worker boundaries are exercised in test_admin_mfa.py.
    app = create_app(Settings(data_dir=tmp_path, groq_key="", admin_mfa_required=False))
    with TestClient(app) as client:
        token = (tmp_path / '.bootstrap-token').read_text()
        response = post(client, '/setup', {"email": "owner@example.test", "password": PASSWORD, "token": token})
        assert response.status_code == 200, response.text
        yield app, client, tmp_path


def asset(client):
    response = post(client, '/assets', {"name": "Fixture portal", "kind": "application", "owner": "Fixture team", "environment": "staging", "criticality": "high", "authorized": True})
    assert response.status_code == 200, response.text
    return response.json()


def scan(client, identifier, content='import hashlib\ndef store_password(password):\n    return hashlib.sha256(password.encode()).hexdigest()\n', label='auth.py'):
    result = post(client, '/scans', {"asset_id": identifier, "kind": "python", "label": label, "content": content, "authorized": True})
    assert result.status_code == 200, result.text
    return result.json()


def invited(app, owner_client, role='reviewer', email='reviewer@example.test'):
    invite = post(owner_client, '/invites', {"email": email, "role": role})
    assert invite.status_code == 200, invite.text
    client = TestClient(app)
    joined = post(client, '/join', {"email": email, "password": PASSWORD, "token": invite.json()['token']})
    assert joined.status_code == 200, joined.text
    return client


def data(client):
    result = client.get('/api/workspace')
    assert result.status_code == 200
    return result.json()


def test_bootstrap_is_one_time_and_no_default_data(system):
    app, client, path = system
    assert not (path / '.bootstrap-token').exists()
    assert client.get('/api/status').json()['setup_required'] is False
    assert post(client, '/setup', {"email": "other@example.test", "password": PASSWORD, "token": "wrong"}).status_code == 409
    assert not data(client)['assets']
    assert 'sentinel_session=' in client.cookies.__str__() or client.cookies.get('sentinel_session')
    with app.state.store.connect() as c:
        user = c.execute('SELECT password FROM users').fetchone()[0]
        assert PASSWORD not in user
        session_token = c.execute('SELECT token FROM sessions').fetchone()[0]
        assert session_token != client.cookies.get('sentinel_session')


def test_advanced_interface_is_opt_in_without_disabling_scanning_engines(system, monkeypatch):
    app, client, _ = system
    monkeypatch.delenv('ADVANCED_UI', raising=False)
    assert Settings().advanced_ui is False
    app.state.settings.advanced_ui = False
    assert data(client)['features'] == {'advanced_ui': False}
    assert client.get('/advanced').status_code == 404
    # The flag gates legacy UI only: existing approved worker routes still work.
    assert scan(client, asset(client)['id'])['finding_ids']
    monkeypatch.setenv('ADVANCED_UI', 'true')
    assert Settings().advanced_ui is True
    app.state.settings.advanced_ui = True
    assert data(client)['features'] == {'advanced_ui': True}
    advanced, normal = client.get('/advanced'), client.get('/')
    assert advanced.status_code == normal.status_code
    assert advanced.content == normal.content


def test_unauthorized_csrf_origin_and_validation_redaction(system):
    app, client, _ = system
    assert TestClient(app).get('/api/workspace').status_code == 401
    payload = {"name": "Unauthenticated workspace"}
    assert client.post('/api/workspaces', json=payload).status_code == 403
    result = client.post('/api/login', json={"email": "owner@example.test", "password": PASSWORD}, headers={"Origin": "https://attacker.invalid"})
    assert result.status_code == 403
    result = client.post('/api/login', json={"email": "owner@example.test", "password": PASSWORD, "unexpected": "never-echo-this-secret"})
    assert result.status_code == 422
    assert 'never-echo' not in result.text and PASSWORD not in result.text
    assert client.post('/api/login', content='x' * 160001).status_code == 413


def test_scan_evidence_dedup_and_no_raw_persistence(system):
    app, client, path = system
    identifier = asset(client)['id']
    raw = 'api_key = "synthetic-fixture-secret-never-real"\n'
    first = scan(client, identifier, raw)
    second = scan(client, identifier, raw)
    assert first['finding_ids'] == second['finding_ids']
    assert len(data(client)['findings']) == 1
    assert 'synthetic-fixture-secret' not in json.dumps(data(client))
    with app.state.store.connect() as c:
        assert 'synthetic-fixture-secret' not in str([r[0] for r in c.execute('SELECT data FROM entities')])
    scan(client, identifier, 'import secrets\ntoken = secrets.token_urlsafe(32)\n')
    assert data(client)['findings'][0]['observed_in_latest'] is False
    assert data(client)['findings'][0]['status'] == 'open'


def test_independent_review_reopen_and_case_workflow(system):
    app, client, _ = system
    reviewer = invited(app, client)
    identifier = asset(client)['id']
    finding_id = scan(client, identifier)['finding_ids'][0]
    owner_id = client.get('/api/me').json()['id']
    case = post(client, '/investigations', {"title": "Investigate password storage", "finding_ids": [finding_id]}).json()
    assert post(reviewer, '/investigations/' + case['id'], {"status": "closed", "note": "Closing without evidence"}).status_code == 409
    task = post(client, '/tasks', {"finding_id": finding_id, "assignee": owner_id}).json()
    assert post(client, '/tasks', {"finding_id": finding_id, "assignee": owner_id}).status_code == 409
    assert post(client, '/tasks/' + task['id'], {"action": "approve", "evidence": "An invalid state transition"}).status_code == 409
    assert post(client, '/tasks/' + task['id'], {"action": "submit", "evidence": "Changed to scrypt; tests verified in commit abc123"}).status_code == 200
    assert post(client, '/tasks/' + task['id'], {"action": "approve", "evidence": "Self approval must be forbidden"}).status_code == 403
    result = post(reviewer, '/tasks/' + task['id'], {"action": "approve", "evidence": "Independent review verified code and regression results"})
    assert result.status_code == 200, result.text
    assert data(client)['findings'][0]['status'] == 'resolved'
    assert post(reviewer, '/investigations/' + case['id'], {"status": "closed", "note": "Verified independent review and linked resolution"}).status_code == 200
    scan(client, identifier)
    assert data(client)['findings'][0]['status'] == 'open'
    assert data(client)['tasks'][0]['status'] == 'open'
    assert data(client)['investigations'][0]['status'] == 'investigating'
    assert data(client)['audit']['valid']


def test_rescan_invalidates_pending_review(system):
    app, client, _ = system
    reviewer = invited(app, client)
    identifier = asset(client)['id']
    finding_id = scan(client, identifier)['finding_ids'][0]
    task = post(client, '/tasks', {"finding_id": finding_id, "assignee": client.get('/api/me').json()['id']}).json()
    post(client, '/tasks/' + task['id'], {"action": "submit", "evidence": "Fixture change and test evidence"})
    scan(client, identifier)
    assert post(reviewer, '/tasks/' + task['id'], {"action": "approve", "evidence": "Evidence has changed since submission"}).status_code == 409


def test_viewer_and_tenant_boundaries(system):
    app, client, _ = system
    viewer = invited(app, client, 'viewer', 'viewer@example.test')
    original = client.get('/api/me').json()['workspace']
    original_asset = asset(client)['id']
    finding_id = scan(client, original_asset)['finding_ids'][0]
    assert viewer.get('/api/report').status_code == 200
    assert post(viewer, '/workspaces', {"name": "Viewer independent space"}).status_code == 200
    assert post(viewer, '/assets', {"name": "Denied", "kind": "service", "owner": "Fixture", "environment": "staging", "criticality": "low", "authorized": True}).status_code == 403
    independent = post(client, '/workspaces', {"name": "Separate team"}).json()['id']
    post(client, '/workspaces/' + independent + '/switch', {})
    assert data(client)['assets'] == []
    assert post(client, '/scans', {"asset_id": original_asset, "kind": "python", "label": "cross-scope", "content": "x=1", "authorized": True}).status_code == 404
    assert post(client, '/investigations', {"title": "Denied cross scope", "finding_ids": [finding_id]}).status_code == 404
    assert post(viewer, '/workspaces/' + independent + '/switch', {}).status_code == 404
    assert post(client, '/workspaces/' + original + '/switch', {}).status_code == 200


def test_demo_is_removed_and_old_training_memberships_are_not_exposed(system):
    app, client, _ = system
    assert post(client, '/demo', {}).status_code == 404
    me = client.get('/api/me').json()
    with app.state.store.connect(write=True) as c:
        identifier = uid()
        c.execute('INSERT INTO workspaces VALUES(?,?,1)', (identifier, 'Legacy training'))
        c.execute('INSERT INTO members VALUES(?,?,?)', (identifier, me['id'], 'owner'))
    assert all(w['demo'] == 0 for w in client.get('/api/me').json()['workspaces'])
    assert post(client, '/workspaces/' + identifier + '/switch', {}).status_code == 404
    assert not data(client)['assets']


def test_mfa_enrollment_login_replay_recovery_and_disable(system):
    app, client, _ = system
    response = post(client, '/mfa/setup', {"password": PASSWORD})
    assert response.status_code == 200, response.text
    secret = response.json()['secret']
    assert post(client, '/mfa/enable', {"code": "wrong-code"}).status_code == 401
    code = totp(secret, int(time.time() // 30))
    enabled = post(client, '/mfa/enable', {"code": code})
    assert enabled.status_code == 200, enabled.text
    recovery = enabled.json()['recovery_codes']
    assert len(recovery) == 8
    with app.state.store.connect() as c:
        user = c.execute('SELECT * FROM users').fetchone()
        assert secret not in user['mfa']
        assert recovery[0] not in user['recovery']
    post(client, '/logout', {})
    signed = post(client, '/login', {"email": "owner@example.test", "password": PASSWORD})
    assert signed.json()['mfa_required']
    assert client.get('/api/me').status_code == 401
    headers = {'X-CSRF-Token': signed.json()['csrf']}
    assert client.post('/api/login/factor', json={"code": code}, headers=headers).status_code == 401
    result = client.post('/api/login/factor', json={"code": recovery[0]}, headers=headers)
    assert result.status_code == 200
    assert client.get('/api/me').json()['recovery_remaining'] == 7
    assert post(client, '/mfa/setup', {"password": PASSWORD}).status_code == 409
    assert post(client, '/mfa/disable', {"password": PASSWORD, "code": recovery[0]}).status_code == 401
    assert post(client, '/mfa/disable', {"password": PASSWORD, "code": recovery[1]}).status_code == 200
    assert not client.get('/api/me').json()['mfa_enabled']


def test_mfa_existing_account_invitation_cannot_bypass_factor(system):
    app, client, _ = system
    secret = post(client, '/mfa/setup', {"password": PASSWORD}).json()['secret']
    enabled = post(client, '/mfa/enable', {"code": totp(secret, int(time.time() // 30))}).json()
    second = post(client, '/workspaces', {"name": "Other workspace"}).json()['id']
    # Make a separate owner in another isolated app space to issue a valid invitation.
    new_user = invited(app, client, 'analyst', 'other@example.test')
    outsider_space = post(new_user, '/workspaces', {"name": "Outsider owned"}).json()['id']
    post(new_user, '/workspaces/' + outsider_space + '/switch', {})
    token = post(new_user, '/invites', {"email": "owner@example.test", "role": "viewer"}).json()['token']
    other_session = TestClient(app)
    assert post(other_session, '/join', {"email": "owner@example.test", "password": PASSWORD, "token": token}).status_code == 401
    assert post(other_session, '/join', {"email": "owner@example.test", "password": PASSWORD, "token": token, "code": enabled['recovery_codes'][0]}).status_code == 200


def test_agent_unconfigured_is_explicit_and_report_checksum(system):
    _, client, _ = system
    identifier = scan(client, asset(client)['id'])['finding_ids'][0]
    assert post(client, '/agents', {"finding_ids": [identifier], "mode": "triage"}).status_code == 503
    report = client.get('/api/report').json()
    checksum = report.pop('content_sha256')
    from backend.store import canonical
    import hashlib
    assert hashlib.sha256(canonical(report).encode()).hexdigest() == checksum
    assert report['audit']['valid']


def test_agent_pipeline_only_sends_allowlisted_evidence_and_checks_ids(system):
    app, client, _ = system
    identifier = scan(client, asset(client)['id'])['finding_ids'][0]
    workspace = client.get('/api/me').json()['workspace']
    with app.state.store.connect() as c:
        finding = Store.get(c, workspace, 'findings', identifier)
    finding['evidence'] = 'secret-in-raw-evidence-should-not-leave'
    evidence = agents.collect_evidence([finding])
    assert 'secret-in-raw' not in json.dumps(evidence)
    seen = []
    def provider(request):
        seen.append(json.loads(request.content))
        plan = {"summary": "A fixture plan for review", "recommendations": [{"finding_id": identifier, "priority_reason": "Password verifiers need a slow hash", "actions": ["Use scrypt with a unique salt"], "verification": "Review a migration test and verifier parameters"}]}
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(plan)}}]})
    result = agents.request_plan(evidence, 'fixture-only', 'fixture-model', 'remediation', httpx.MockTransport(provider))
    assert result['recommendations'][0]['finding_id'] == identifier
    assert len(seen) == 1
    with pytest.raises(ValueError):
        agents.request_plan(evidence, 'fixture-only', 'fixture-model', 'triage', httpx.MockTransport(lambda request: httpx.Response(429)))
    with pytest.raises(ValueError):
        agents.request_plan(evidence, 'fixture-only', 'fixture-model', 'triage', httpx.MockTransport(lambda request: httpx.Response(200, json={'choices':[{'message':{'content':json.dumps({'summary':'Invented references','recommendations':[{'finding_id':'invented','priority_reason':'Invalid reference','actions':['Do something'],'verification':'Check something'}]})}}]})))


def queue_workflow(app, client, monkeypatch, identifier, **permissions):
    app.state.settings.groq_key = 'fixture-key-only'
    monkeypatch.setattr(app.state.executor, 'submit', lambda *args: None)
    result = post(client, '/agents', {"finding_ids": [identifier], "mode": "remediation", **permissions})
    assert result.status_code == 200, result.text
    return result.json()


def workflow_provider(callback=None):
    def respond(request):
        content = json.loads(request.content)
        evidence = json.loads(content['messages'][1]['content'])['evidence']
        assert all(set(f) == {'finding_id', 'rule', 'title', 'severity', 'confidence', 'guidance', 'reference'} for f in evidence)
        if callback:
            callback()
        plan = {"summary": "Fixture remediation work for independent review", "recommendations": [{"finding_id": f['finding_id'], "priority_reason": "Use a reviewed password hashing function", "actions": ["Implement scrypt with a unique random salt"], "verification": "Test password verification and parameters before submitting"} for f in evidence]}
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(plan)}}]})
    return httpx.MockTransport(respond)


def execute_workflow(app, client, job, transport=None):
    workspace = client.get('/api/me').json()['workspace']
    agents.run_job(app.state.store, workspace, job['id'], 'fixture-key-only', 'fixture-model', transport or workflow_provider())
    return next(j for j in data(client)['jobs'] if j['id'] == job['id'])


def test_authorized_workflow_creates_real_items_and_does_not_approve_them(system, monkeypatch):
    app, client, _ = system
    identifier = scan(client, asset(client)['id'])['finding_ids'][0]
    job = queue_workflow(app, client, monkeypatch, identifier, create_tasks=True, create_investigation=True)
    result = execute_workflow(app, client, job)
    assert result['status'] == 'complete'
    assert len(result['steps']) == 5
    assert len(result['output']['tasks']) == 1
    assert result['output']['investigation']
    workspace = data(client)
    task = workspace['tasks'][0]
    assert task['agent_job'] == job['id']
    assert task['agent_guidance']['finding_id'] == identifier
    assert task['status'] == 'open' and not task.get('evidence')
    assert task['assignee'] == client.get('/api/me').json()['id']
    assert workspace['findings'][0]['status'] == 'open'
    assert result['progress']['checks'][0]['state'] == 'awaiting_recheck'
    assert workspace['audit']['valid']
    execute_workflow(app, client, job)
    assert len(data(client)['tasks']) == 1
    assert len(data(client)['investigations']) == 1
    assert post(client, '/tasks/' + task['id'], {'action': 'submit', 'evidence': 'Fixture implementation and regression test evidence'}).status_code == 200
    assert post(client, '/tasks/' + task['id'], {'action': 'approve', 'evidence': 'Cannot approve my own submitted agent task'}).status_code == 403


def test_workflow_requires_explicit_write_scope_and_reuses_existing_tasks(system, monkeypatch):
    app, client, _ = system
    identifier = scan(client, asset(client)['id'])['finding_ids'][0]
    draft = queue_workflow(app, client, monkeypatch, identifier)
    assert execute_workflow(app, client, draft)['output']['status'] == 'draft_only'
    assert not data(client)['tasks'] and not data(client)['investigations']
    existing = post(client, '/tasks', {'finding_id': identifier, 'assignee': client.get('/api/me').json()['id']}).json()
    job = queue_workflow(app, client, monkeypatch, identifier, create_tasks=True)
    output = execute_workflow(app, client, job)['output']
    assert output['tasks'] == [] and output['reused_tasks'] == [existing['id']]
    assert len(data(client)['tasks']) == 1


def test_workflow_discards_writes_when_evidence_changes_during_model_request(system, monkeypatch):
    app, client, _ = system
    target = asset(client)['id']
    identifier = scan(client, target)['finding_ids'][0]
    job = queue_workflow(app, client, monkeypatch, identifier, create_tasks=True, create_investigation=True)
    result = execute_workflow(app, client, job, workflow_provider(lambda: scan(client, target)))
    assert result['status'] == 'failed' and 'Evidence changed' in result['error']
    assert not data(client)['tasks'] and not data(client)['investigations']


def test_workflow_rechecks_permissions_and_provider_failure_cannot_dispatch(system, monkeypatch):
    app, client, _ = system
    identifier = scan(client, asset(client)['id'])['finding_ids'][0]
    job = queue_workflow(app, client, monkeypatch, identifier, create_tasks=True)
    def demote():
        with app.state.store.connect(write=True) as c:
            c.execute("UPDATE members SET role='viewer'")
    result = execute_workflow(app, client, job, workflow_provider(demote))
    assert result['status'] == 'failed' and 'permission was removed' in result['error']
    assert not data(client)['tasks']
    with app.state.store.connect(write=True) as c:
        c.execute("UPDATE members SET role='owner'")
    failed = queue_workflow(app, client, monkeypatch, identifier, create_tasks=True)
    result = execute_workflow(app, client, failed, httpx.MockTransport(lambda request: httpx.Response(429)))
    assert result['status'] == 'failed' and not data(client)['tasks']


def test_workflow_progress_distinguishes_rechecks_from_fix_approval(system, monkeypatch):
    app, client, _ = system
    target = asset(client)['id']
    identifier = scan(client, target)['finding_ids'][0]
    job = queue_workflow(app, client, monkeypatch, identifier, create_tasks=True)
    execute_workflow(app, client, job)
    scan(client, target)
    progress = post(client, '/agents/' + job['id'] + '/progress', {}).json()
    assert progress['checks'][0]['state'] == 'still_observed'
    scan(client, target, content='def add(a, b):\n    return a + b\n')
    progress = post(client, '/agents/' + job['id'] + '/progress', {}).json()
    assert progress['checks'][0]['state'] == 'not_observed_in_recheck'
    assert data(client)['findings'][0]['status'] == 'open'
    task = data(client)['tasks'][0]
    post(client, '/tasks/' + task['id'], {'action': 'submit', 'evidence': 'Fixture corrected source and regression tests verified'})
    reviewer = invited(app, client)
    approved = post(reviewer, '/tasks/' + task['id'], {'action': 'approve', 'evidence': 'Independent fixture review of source and test evidence'})
    assert approved.status_code == 200
    progress = post(client, '/agents/' + job['id'] + '/progress', {}).json()
    assert progress['checks'][0]['state'] == 'resolved_by_review'


def test_agent_progress_denies_viewers_and_unfinished_jobs(system, monkeypatch):
    app, client, _ = system
    identifier = scan(client, asset(client)['id'])['finding_ids'][0]
    job = queue_workflow(app, client, monkeypatch, identifier)
    assert post(client, '/agents/' + job['id'] + '/progress', {}).status_code == 409
    execute_workflow(app, client, job)
    viewer = invited(app, client, role='viewer')
    assert post(viewer, '/agents/' + job['id'] + '/progress', {}).status_code == 403
    other = post(client, '/workspaces', {'name': 'Separate agent workspace'}).json()['id']
    assert post(client, '/workspaces/' + other + '/switch', {}).status_code == 200
    assert post(client, '/agents/' + job['id'] + '/progress', {}).status_code == 404


def test_progress_partial_recheck_is_inconclusive_and_tool_writes_are_atomic(system, monkeypatch):
    app, client, _ = system
    identifier = scan(client, asset(client)['id'])['finding_ids'][0]
    job = queue_workflow(app, client, monkeypatch, identifier, create_tasks=True, create_investigation=True)
    original_put = Store.put
    def fail_case(c, workspace, kind, value):
        if kind == 'investigations':
            raise RuntimeError('Fixture failed tool write')
        return original_put(c, workspace, kind, value)
    with monkeypatch.context() as patch:
        patch.setattr(Store, 'put', staticmethod(fail_case))
        result = execute_workflow(app, client, job)
    assert result['status'] == 'failed'
    assert not data(client)['tasks'] and not data(client)['investigations']
    job = queue_workflow(app, client, monkeypatch, identifier)
    execute_workflow(app, client, job)
    workspace = client.get('/api/me').json()['workspace']
    with app.state.store.connect(write=True) as c:
        previous = Store.all(c, workspace, 'scans')[0]
        previous.update(id=uid(), status='partial', finding_ids=[])
        Store.put(c, workspace, 'scans', previous)
    progress = post(client, '/agents/' + job['id'] + '/progress', {}).json()
    assert progress['checks'][0]['state'] == 'inconclusive_recheck'


def test_audit_tampering_detected(system):
    app, client, _ = system
    asset(client)
    with app.state.store.connect(write=True) as c:
        c.execute("UPDATE audit SET action='modified' WHERE seq=1")
    assert data(client)['audit']['valid'] is False


def test_security_headers_cookies_and_host(system):
    _, client, _ = system
    response = client.get('/api/me')
    assert response.headers['x-frame-options'] == 'DENY'
    assert 'object-src' in response.headers['content-security-policy']
    signed = post(client, '/login', {"email":"owner@example.test", "password":PASSWORD})
    cookie = signed.headers['set-cookie']
    assert 'HttpOnly' in cookie and 'SameSite=strict' in cookie
    assert client.get('/api/status', headers={'host':'hostile.invalid'}).status_code == 400
    with pytest.raises(ValueError):
        Settings(origin='http://public.example.com')


def test_login_throttle_counts_failures(system):
    _, client, _ = system
    for _ in range(12):
        assert post(client, '/login', {"email":"absent@example.test", "password":"wrong"}).status_code == 401
    assert post(client, '/login', {"email":"absent@example.test", "password":"wrong"}).status_code == 429
