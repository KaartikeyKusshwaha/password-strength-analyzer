from unittest.mock import patch
from backend.app import OperationRequest
from test_platform import system, post, data, asset

MESSAGE = 'From: private-from@sender.test\nReply-To: private-reply@other.test\nTo: private-to@recipient.test\nSubject: Private fixture subject\nContent-Type: text/html; charset=utf-8\n\n<a href="https://other.test/private-token">https://bank.test</a>'


def test_email_operation_parses_eml_records_only_sanitized_evidence(system):
    app, client, _ = system
    body = dict(action='email', content=MESSAGE, email_format='eml', authorized=True)
    with patch.object(app.state.executor, 'submit'):
        response = post(client, '/operations', body)
    assert response.status_code == 200
    me = client.get('/api/me').json()
    app.state.run_operation(me['workspace'], me['id'], response.json()['id'], OperationRequest(**body))
    workspace = data(client)
    assert workspace['operations'][0]['status'] == 'complete'
    assert {f['rule'] for f in workspace['findings']} == {'MAIL004', 'MAIL005'}
    assert workspace['scans'][0]['mail_coverage']['sender_authentication'] == 'unverified'
    with app.state.store.connect() as c:
        serialized = '\n'.join(row[0] for row in c.execute('SELECT data FROM entities'))
    assert all(raw not in serialized for raw in ['private-token', 'private-from', 'private-reply', 'Private fixture subject', 'bank.test'])
    assert workspace['audit']['valid']


def test_message_scope_keeps_separate_messages_and_reuses_identical_submission(system):
    _, client, _ = system
    identifier = asset(client)['id']
    def submit(content):
        response = post(client, '/scans', dict(asset_id=identifier, kind='email', label='Message review', content=content, email_format='eml', authorized=True))
        assert response.status_code == 200, response.text
        return response.json()
    first = submit(MESSAGE)
    second = submit(MESSAGE.replace('Private fixture subject', 'Another message'))
    assert first['finding_ids'] != second['finding_ids']
    assert len(data(client)['findings']) == 4
    assert all(f['observed_in_latest'] for f in data(client)['findings'])
    repeated = submit(MESSAGE)
    assert repeated['finding_ids'] == first['finding_ids']
    assert len(data(client)['findings']) == 4


def test_invalid_eml_does_not_record_text_fallback_and_unknown_format_rejected(system):
    _, client, _ = system
    identifier = asset(client)['id']
    for format in ['eml', 'unknown']:
        response = post(client, '/scans', dict(asset_id=identifier, kind='email', label='Invalid message', content='URGENT verify password', email_format=format, authorized=True))
        assert response.status_code == 422
    assert not data(client)['scans']


def test_partial_mail_coverage_stays_partial_in_combined_review(system):
    app, client, _ = system
    me = client.get('/api/me').json()
    with patch.object(app.state.executor, 'submit') as submit:
        response = post(client, '/security-reviews', dict(workspace_id=me['workspace'], name='Mail review', authorized=True, checks=[dict(action='email',email_format='eml',content='From: x@example.test\nContent-Type: text/plain; charset=unknown-fixture\n\ntext', authorized=True)]))
    assert response.status_code == 200
    arguments = submit.call_args.args
    arguments[0](*arguments[1:])
    workspace = data(client)
    assert workspace['security_reviews'][0]['status'] == 'partial'
    assert workspace['scans'][0]['status'] == 'partial'


def test_mail_agent_only_receives_allowlisted_rules_and_other_messages_are_not_rechecks(system):
    import json
    import httpx
    from backend import agents
    app, client, _ = system
    app.state.settings.groq_key = 'fixture-only'
    calls = []
    def respond(request):
        content = json.loads(request.content)
        assert all(raw not in request.content.decode() for raw in ['private-token', 'private-from', 'bank.test', 'message_digest', 'Authentication-Results'])
        evidence = json.loads(content['messages'][1]['content'])['evidence']
        calls.append(evidence)
        return httpx.Response(200, json={'choices':[{'message':{'content':json.dumps({'summary':'Review message routing and link destinations independently','recommendations':[dict(finding_id=f['finding_id'],priority_reason='Review the recorded message indicator',actions=['Verify through a previously trusted channel'],verification='Record independent verification of the sender and request') for f in evidence]})}}]})
    app.state.agent_transport = httpx.MockTransport(respond)
    me = client.get('/api/me').json()
    with patch.object(app.state.executor, 'submit') as submit:
        response = post(client, '/security-reviews', dict(workspace_id=me['workspace'], name='Email agent review', authorized=True, ai_triage=True, checks=[dict(action='email',email_format='eml',content=MESSAGE,authorized=True)]))
    assert response.status_code == 200
    arguments = submit.call_args.args
    arguments[0](*arguments[1:])
    workspace = data(client)
    job = workspace['jobs'][0]
    assert job['status'] == 'complete' and len(workspace['tasks']) == 2 and len(calls) == 1
    assert {f['rule'] for f in calls[0]} == {'MAIL004', 'MAIL005'}
    with patch.object(app.state.executor, 'submit'):
        response = post(client, '/operations', dict(action='email',email_format='eml',content=MESSAGE.replace('Private fixture subject','Different message'),authorized=True))
    app.state.run_operation(me['workspace'],me['id'],response.json()['id'],OperationRequest(action='email',email_format='eml',content=MESSAGE.replace('Private fixture subject','Different message'),authorized=True))
    with app.state.store.connect(write=True) as c:
        progress = agents.check_progress(c,me['workspace'],job)
    assert all(row['state']=='awaiting_recheck' for row in progress['checks'])
