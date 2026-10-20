from unittest.mock import patch

import pytest
from backend import device_checks
from backend.app import OperationRequest, Settings, create_app
from backend.store import Store
from test_platform import asset, data, invited, post, system


def queue(app, client, monkeypatch, **changes):
    monkeypatch.setattr(app.state.executor, 'submit', lambda *args: None)
    body = {"action":'device', "target":'127.0.0.1', "ports":[22, 443], "authorized":True, **changes}
    result = post(client, '/operations', body)
    assert result.status_code == 200, result.text
    return result.json(), OperationRequest(**body)


def execute(app, client, operation, body):
    me = client.get('/api/me').json()
    app.state.run_operation(me['workspace'], me['id'], operation['id'], body)
    return next(o for o in data(client)['operations'] if o['id'] == operation['id'])


def test_real_device_operation_creates_asset_scan_and_findings_without_import(system, monkeypatch):
    app, client, _ = system
    operation, body = queue(app, client, monkeypatch)
    def check(pair, timeout):
        assert pair[0] == '127.0.0.1' and pair[1] in {22, 443}
        assert timeout <= .5
        if pair[1] == 443:
            raise ConnectionRefusedError()
        from contextlib import nullcontext
        return nullcontext()
    with patch.object(device_checks.socket, 'create_connection', side_effect=check):
        result = execute(app, client, operation, body)
    assert result['status'] == 'complete' and result['scan_id']
    assert len(result['finding_ids']) == 1
    current = data(client)
    assert len(current['assets']) == len(current['scans']) == len(current['findings']) == 1
    assert current['findings'][0]['port'] == 22
    assert current['findings'][0]['severity'] == 'unknown'
    assert current['audit']['valid']
    # The same queued worker cannot run twice.
    execute(app, client, operation, body)
    assert len(data(client)['scans']) == 1
    again, body = queue(app, client, monkeypatch)
    assert again['asset_id'] == operation['asset_id']


@pytest.mark.parametrize('target', ['8.8.8.8', '169.254.169.254', '0.0.0.0', '224.0.0.1', 'example.com', '127.0.0.0/8', '::ffff:169.254.169.254', 'fe80::1', '192.168.1.255'])
def test_device_operator_rejects_unapproved_target_types(system, target):
    _, client, _ = system
    assert post(client, '/operations', dict(action='device', target=target, ports=[22], authorized=True)).status_code == 422


def test_device_scope_auth_and_hosted_server_cannot_masquerade_as_users_computer(system, monkeypatch):
    app, client, _ = system
    assert post(client, '/operations', dict(action='device', authorized=False)).status_code == 422
    assert post(client, '/operations', dict(action='device', ports=[0], authorized=True)).status_code == 422
    assert post(client, '/operations', dict(action='device', ports=list(range(1, 66)), authorized=True)).status_code == 422
    app.state.settings.secure = True
    assert post(client, '/operations', dict(action='device', authorized=True)).status_code == 409
    app.state.settings.secure = False
    viewer = invited(app, client, role='viewer')
    assert post(viewer, '/operations', dict(action='device', authorized=True)).status_code == 403
    operation, body = queue(app, client, monkeypatch)
    with app.state.store.connect(write=True) as c:
        c.execute("UPDATE members SET role='viewer'")
    with patch.object(device_checks, 'assess') as assess:
        assert execute(app, client, operation, body)['status'] == 'failed'
    assess.assert_not_called()


def test_operation_failure_and_partial_results_are_honest(system, monkeypatch):
    app, client, _ = system
    operation, body = queue(app, client, monkeypatch)
    with patch.object(device_checks.socket, 'create_connection', side_effect=TimeoutError):
        result = execute(app, client, operation, body)
    assert result['status'] == 'partial' and result['finding_ids'] == []
    assert all(p['status'] == 'unassessed' for p in data(client)['scans'][0]['observations'])
    operation, body = queue(app, client, monkeypatch)
    with patch.object(device_checks, 'assess', side_effect=RuntimeError('internal fixture details')):
        result = execute(app, client, operation, body)
    assert result['status'] == 'failed' and 'internal fixture' not in result['error']


def test_content_operation_does_not_persist_raw_source_and_creates_no_fake_ai(system, monkeypatch):
    app, client, _ = system
    secret = 'fixture-secret-never-persist-123'
    operation, body = queue(app, client, monkeypatch, action='python', content=f'import hashlib\n# {secret}\ndef verify(password):\n return hashlib.sha256(password.encode()).hexdigest()')
    result = execute(app, client, operation, body)
    assert result['status'] == 'complete' and result['finding_ids']
    assert secret not in str(data(client)) and secret not in client.get('/api/report').text
    assert not data(client)['jobs']
    assert post(client, '/operations', dict(action='python', content='pass', authorized=True, ai_triage=True)).status_code == 503


def test_operation_duplicate_queue_and_workspace_isolation(system, monkeypatch):
    app, client, _ = system
    operation, body = queue(app, client, monkeypatch)
    assert post(client, '/operations', dict(action='device', authorized=True)).status_code == 409
    other = post(client, '/workspaces', {'name':'Separate operations'}).json()['id']
    post(client, '/workspaces/' + other + '/switch', {})
    assert data(client)['operations'] == []
    assert data(client)['assets'] == []


def test_ai_can_dispatch_from_real_scan_only_with_explicit_scope(system, monkeypatch):
    from test_platform import workflow_provider
    app, client, _ = system
    app.state.settings.groq_key = 'fixture-only'
    app.state.agent_transport = workflow_provider()
    operation, body = queue(app, client, monkeypatch, action='python', content='import hashlib\ndef verify(password):\n return hashlib.sha256(password.encode()).hexdigest()', ai_triage=True)
    result = execute(app, client, operation, body)
    assert result['agent_job']
    current = data(client)
    assert current['jobs'][0]['status'] == 'complete'
    assert len(current['tasks']) == 1 and current['tasks'][0]['status'] == 'open'


def test_private_targets_remain_one_address_and_bounded_ports():
    assert device_checks.validate_target('192.168.1.10') == '192.168.1.10'
    assert device_checks.validate_target('::1') == '::1'
    for ports in [[], [65536], [True]]:
        with pytest.raises(ValueError):
            device_checks.assess('127.0.0.1', ports)


def test_device_operator_observes_a_real_owned_tcp_listener():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        result = device_checks.assess('127.0.0.1', [port])
    assert result['observations'] == [{'host':'127.0.0.1', 'port':port, 'status':'open'}]
    assert result['findings'][0]['port'] == port
    assert result['findings'][0]['severity'] == 'unknown'
