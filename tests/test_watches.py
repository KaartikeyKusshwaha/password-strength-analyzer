import json
from unittest.mock import patch

import httpx
import pytest

from backend import scanner
from backend.store import Store
from test_platform import system,post,data,invited


def configuration(**values):
    return dict(name='Client portal',format='requirements',content='requests==2.32.3',consent=True,**values)


def create(client,**values):
    response=post(client,'/watches',configuration(**values))
    assert response.status_code==200,response.text
    return response.json()


def transport(results):
    def respond(request):
        if request.method=='GET':
            return httpx.Response(200,json={'id':request.url.path.rsplit('/',1)[-1],'aliases':[]})
        assert str(request.url)=='https://api.osv.dev/v1/querybatch'
        payload=json.loads(request.content)
        assert set(payload)=={'queries'} and all(set(q)=={'package','version'} for q in payload['queries'])
        return httpx.Response(200,json={'results':results})
    return httpx.MockTransport(respond)


def run(app,client,watch,results):
    service=app.state.watch_service;service.transport=transport(results)
    with patch.object(service.executor,'submit'):
        response=post(client,f"/watches/{watch['id']}/check",{})
    assert response.status_code==200,response.text
    service.run(client.get('/api/me').json()['workspace'],response.json()['id'])
    return client.get('/api/watches').json()


def test_watch_requires_explicit_consent_and_exact_inventory(system):
    app,client,_=system
    assert post(client,'/watches',{**configuration(),'consent':False}).status_code==422
    for content in ('requests>=2','requests==2.0; python_version>"3"','requests==2.0\nrequests==3.0','-r other.txt'):
        assert post(client,'/watches',{**configuration(),'content':content}).status_code==422
    watch=create(client)
    assert not watch['enabled'] and watch['next_due'] is None
    assert 'content' not in watch
    assert data(client)['assets'][0]['watch_id']==watch['id']


def test_alerts_are_deduplicated_tasks_opt_in_and_coverage_not_inferred(system):
    app,client,_=system;watch=create(client,create_tasks=True)
    result=run(app,client,watch,[{'vulns':[{'id':'GHSA-fixture-123'}]}])
    assert result['runs'][0]['status']=='complete'
    assert len(data(client)['tasks'])==1
    run(app,client,watch,[{'vulns':[{'id':'GHSA-fixture-123'}]}])
    assert len(client.get('/api/notifications').json()['notifications'])==1
    run(app,client,watch,[{'next_page_token':'fixture-page'}])
    assert client.get('/api/watches').json()['runs'][0]['status']=='partial'
    run(app,client,watch,[{'vulns':[{'id':'GHSA-fixture-123'}]}])
    alerts=client.get('/api/notifications').json()['notifications']
    assert [n['kind'] for n in alerts].count('advisory')==1
    assert {n['kind'] for n in alerts}=={'advisory','coverage_lost','coverage_restored'}
    assert len(data(client)['tasks'])==1


def test_schedules_claim_once_pause_and_edit_cancel_stale_results(system):
    app,client,_=system;service=app.state.watch_service;service.clock=lambda:1000
    watch=create(client,enabled=True,interval_hours=6)
    assert watch['next_due']==22600
    assert service.tick() is None
    service.clock=lambda:22601
    with patch.object(service.executor,'submit') as submit:
        chosen=service.tick();assert chosen
        assert service.tick() is None and submit.call_count==1
        updated=post(client,f"/watches/{watch['id']}/update",{**configuration(),'content':'requests==2.32.4','revision':1})
    assert updated.status_code==200
    with patch.object(scanner,'scan_watch') as external:
        service.run(*chosen);external.assert_not_called()
    assert client.get('/api/watches').json()['runs'][0]['status']=='cancelled'
    assert post(client,f"/watches/{watch['id']}/schedule",{'enabled':True,'revision':1,'consent':True}).status_code==409
    assert post(client,f"/watches/{watch['id']}/schedule",{'enabled':True,'revision':2}).status_code==422


def test_recovery_requires_explicit_resume_and_archiving_retains_evidence(system):
    app,client,_=system;service=app.state.watch_service;watch=create(client,enabled=True)
    with patch.object(service.executor,'submit'):
        queued=post(client,f"/watches/{watch['id']}/check",{}).json()
    service.recover()
    value=client.get('/api/watches').json()
    assert not value['watches'][0]['enabled'] and value['runs'][0]['status']=='interrupted'
    with patch.object(scanner,'scan_watch') as external:
        service.run(client.get('/api/me').json()['workspace'],queued['id']);external.assert_not_called()
    assert post(client,f"/watches/{watch['id']}/archive",{'revision':2}).status_code==200
    assert post(client,f"/watches/{watch['id']}/check",{}).status_code==409
    assert len(data(client)['assets'])==1


def test_permissions_and_per_member_notification_reads(system):
    app,client,_=system;watch=create(client)
    viewer=invited(app,client,'viewer')
    assert post(viewer,'/watches',configuration()).status_code==403
    assert post(viewer,f"/watches/{watch['id']}/check",{}).status_code==403
    run(app,client,watch,[{'vulns':[{'id':'CVE-2025-fixture'}]}])
    notification=client.get('/api/notifications').json()['notifications'][0]
    assert post(client,'/notifications/read',{'ids':[notification['id'],'missing']}).status_code==404
    assert client.get('/api/notifications').json()['unread']==1
    assert post(client,'/notifications/read',{'ids':[notification['id']]}).status_code==200
    assert client.get('/api/notifications').json()['unread']==0
    assert viewer.get('/api/notifications').json()['unread']==1
    assert not data(client)['tasks']


def test_expired_lease_and_removed_owner_never_query_provider(system):
    app,client,_=system;service=app.state.watch_service;service.clock=lambda:1000;watch=create(client)
    with patch.object(service.executor,'submit'):
        queued=post(client,f"/watches/{watch['id']}/check",{}).json()
    service.clock=lambda:1400
    with patch.object(scanner,'scan_watch') as external:
        service.run(client.get('/api/me').json()['workspace'],queued['id']);external.assert_not_called()
    assert client.get('/api/watches').json()['runs'][0]['status']=='interrupted'


@pytest.mark.parametrize('results',[[{}],[{'next_page_token':'more','vulns':[{'id':'CVE-2025-fixture'}]}],[],[{'vulns':[{'id':'https://evil.test'}]}],[{'vulns':[{'id':'x'}]*101}]])
def test_batch_order_pagination_malformed_and_limits(results):
    packages=[{'ecosystem':'PyPI','name':'requests','version':'2.32.3','line':0}]
    value=scanner.scan_watch(packages,transport(results))
    if results==[{}]:assert value['error'] is None and len(value['checked'])==1
    else:assert value['error'] and not value['checked']
    assert all(item['severity']=='unknown' for item in value['findings'])


def test_network_failure_is_incomplete_not_clean():
    def fail(request):raise httpx.ConnectError('private transport details',request=request)
    result=scanner.scan_watch([{'ecosystem':'npm','name':'lodash','version':'4.17.20','line':0}],httpx.MockTransport(fail))
    assert result['error'] and not result['checked'] and 'private transport' not in json.dumps(result)
