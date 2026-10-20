import json
import socket
from unittest.mock import patch

import httpx
import pytest

from backend import scanner
from backend.security import check_totp, totp


@pytest.mark.parametrize('source,rule', [
    ('from hashlib import sha256 as h\ndef login(password):\n return h(password.encode())', 'PY001'),
    ('import random as r\ndef reset_token():\n return r.randint(1,999)', 'PY002'),
    ('import requests as r\nr.get("https://example.test", verify=False)', 'PY003'),
    ('import subprocess as s\ns.run("echo example",shell=True)', 'PY004'),
    ('app.run(debug=True)', 'PY005'),
    ('eval(user_input)', 'PY006'),
    ('response.set_cookie("x", "y", secure=False)', 'PY007'),
    ('SESSION_COOKIE_HTTPONLY=False', 'PY007'),
    ('secret_key="fixture-literal-redacted"', 'PY008'),
])
def test_ast_rules(source, rule):
    result = scanner.scan_python(source)
    assert rule in [f['rule'] for f in result['findings']]
    assert 'fixture-literal' not in json.dumps(result)


def test_checksums_and_unrelated_random_are_not_password_findings():
    source = 'import hashlib\nimport random\nchecksum=hashlib.sha256(file_bytes)\ndice=random.randint(1,6)'
    assert scanner.scan_python(source)['findings'] == []
    with pytest.raises(ValueError):
        scanner.scan_python('this is invalid syntax @')
    with pytest.raises(ValueError):
        scanner.scan_python('a' * 120001)


def test_submitted_code_is_never_executed(tmp_path):
    marker = tmp_path / 'must-not-exist'
    scanner.scan_python(f'open({str(marker)!r}, "w").write("no execution")')
    assert not marker.exists()


def test_email_indicators_no_raw_message_no_false_safe_claim():
    raw = 'URGENT: account suspended. Verify your password at https://bit.ly/private-fixture. Reply with your password.'
    result = scanner.scan_email(raw)
    assert {f['rule'] for f in result['findings']} == {'MAIL001','MAIL002','MAIL003'}
    assert 'private-fixture' not in json.dumps(result)
    assert scanner.scan_email('Meeting notes attached for Monday')['outcome'] == 'No listed indicators found'


def test_dependencies_do_not_silently_resolve_ranges():
    packages, skipped = scanner.parse_dependencies('requests==2.19.1\nflask>=2\n-e .\nfoo==1; os_name=="nt"', 'requirements')
    assert len(packages) == 1 and len(skipped) == 3
    packages, skipped = scanner.parse_dependencies('{"dependencies":{"react":"^19.0.0","lodash":"4.17.20"}}', 'package-json')
    assert len(packages) == 1 and len(skipped) == 1
    with pytest.raises(ValueError):
        scanner.parse_dependencies('[]', 'package-json')


def test_osv_matches_and_partial_failures_are_distinct():
    def provider(request):
        query = json.loads(request.content)
        assert str(request.url) == 'https://api.osv.dev/v1/query'
        if query['package']['name'] == 'fails':
            return httpx.Response(503)
        return httpx.Response(200, json={'vulns':[{'id':'GHSA-fixture-0001','database_specific':{'severity':'HIGH'}}]})
    result = scanner.scan_dependencies('example==1.0.0\nfails==2.0.0', 'requirements', httpx.MockTransport(provider))
    assert len(result['findings']) == 1
    assert len(result['checked']) == 1
    assert result['error'] and result['findings'][0]['severity'] == 'high'
    no_match = scanner.scan_dependencies('example==1.0.0','requirements',httpx.MockTransport(lambda request:httpx.Response(200,json={})))
    assert not no_match['error'] and len(no_match['checked']) == 1 and not no_match['findings']
    malformed = scanner.scan_dependencies('example==1.0.0','requirements',httpx.MockTransport(lambda request:httpx.Response(200,json={'next_page_token':'more'})))
    assert malformed['error'] and not malformed['checked']


def test_website_allowlist_private_ip_and_no_dns_rebind():
    for host in ['localhost','127.0.0.1','example.com/path','https://example.com','example.com:443','user@example.com']:
        with pytest.raises(ValueError):
            scanner.validate_host(host)
    with pytest.raises(ValueError):
        scanner.scan_web('example.com', set())
    with patch.object(socket, 'getaddrinfo', return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))]):
        with pytest.raises(ValueError):
            scanner.scan_web('example.com', {'example.com'})
    with patch.object(socket, 'getaddrinfo', return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('169.254.169.254',443))]):
        with pytest.raises(ValueError):
            scanner.scan_web('example.com', {'example.com'})


def test_headers_respect_csp_frame_ancestors_and_no_cve_inference():
    result = scanner.inspect_headers({'Content-Security-Policy':"default-src 'self'; frame-ancestors 'none'",'Strict-Transport-Security':'max-age=31536000','X-Content-Type-Options':'nosniff','Server':'Apache/2.4.49'})
    assert [f['rule'] for f in result['findings']] == ['WEB005']
    assert 'CVE-' not in json.dumps(result)
    assert 'Apache' not in json.dumps(result)


def test_totp_rfc6238_vector_and_replay():
    secret='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
    assert totp(secret, 1) == '287082'
    assert check_totp(secret, '287082', at=59) == 1
    assert check_totp(secret, '287082', last_step=1, at=59) is None
