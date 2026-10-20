import json
from unittest.mock import patch

import httpx
import pytest

from backend.advisories import enrich
from backend.scanner import finding
from test_platform import system, post, data
from test_watches import create


def item(identifier, name='example', version='1.0.0'):
    return finding('DEP001',advisory=identifier,package={'ecosystem':'PyPI','name':name,'version':version,'line':0})


def provider(records, seen=None):
    def respond(request):
        assert request.method=='GET' and request.url.host=='api.osv.dev'
        identifier=request.url.path.rsplit('/',1)[-1]
        if seen is not None:seen.append(identifier)
        value=records.get(identifier)
        if isinstance(value,httpx.Response):return value
        return httpx.Response(200,json=value if value is not None else {'id':identifier,'aliases':[]})
    return httpx.MockTransport(respond)


def test_transitive_alias_groups_preserve_raw_matches_and_do_not_cross_packages():
    records={'A':{'id':'A','aliases':['CVE-2026-1000']},'B':{'id':'B','aliases':['CVE-2026-2000']},'C':{'id':'C','aliases':['CVE-2026-1000','CVE-2026-2000']}}
    result,coverage=enrich([item('A'),item('B'),item('C'),item('A','other'),item('A',version='2.0.0')],provider(records))
    assert len(result)==3 and coverage==dict(total=3,attempted=3,completed=3,grouped_matches=2,status='complete')
    assert result[0]['matched_advisories']==['A','B','C']
    assert result[0]['advisory_ids']==['A','B','C','CVE-2026-1000','CVE-2026-2000']
    assert all(v['severity']=='unknown' for v in result)
    assert 'reachability is not established' in result[0]['evidence']


@pytest.mark.parametrize('record',[
    {'id':'WRONG','aliases':['B']}, {'id':'A','aliases':['https://evil.test/']},
    {'id':'A','aliases':'B'}, {'id':'A','aliases':['B']*101},
    {'id':'A','withdrawn':'2026-01-01','aliases':['B']},
    httpx.Response(302,headers={'location':'https://evil.test/'}),
    httpx.Response(200,content=b'x'*256001),
])
def test_untrusted_or_unavailable_detail_cannot_hide_a_match(record):
    result,coverage=enrich([item('A'),item('B')],provider({'A':record}))
    assert len(result)==2 and coverage['status']=='partial' and coverage['completed']==1
    assert result[0]['advisory_ids']==['A']
    assert 'evil.test' not in json.dumps(result)


def test_request_cap_and_no_match_case():
    seen=[]
    result,coverage=enrich([item(f'GHSA-{i:03}') for i in range(25)],provider({},seen))
    assert len(seen)==20 and len(result)==25 and coverage['completed']==20 and coverage['status']=='partial'
    result,coverage=enrich([],provider({},seen))
    assert result==[] and coverage['status']=='complete' and len(seen)==20


def test_network_failure_retains_all_raw_matches_without_private_diagnostics():
    def fail(request):raise httpx.ConnectError('private network detail',request=request)
    result,coverage=enrich([item('A'),item('B')],httpx.MockTransport(fail))
    assert len(result)==2 and coverage['completed']==0 and coverage['status']=='partial'
    assert 'private network' not in json.dumps((result,coverage))


def test_watch_groups_tasks_and_retains_finding_when_reported_id_changes(system):
    app,client,_=system
    watch=create(client,create_tasks=True)
    matched=['GHSA-fixture-a','PYSEC-fixture-b']
    def respond(request):
        if request.method=='POST':
            return httpx.Response(200,json={'results':[{'vulns':[{'id':v} for v in matched]}]})
        identifier=request.url.path.rsplit('/',1)[-1]
        return httpx.Response(200,json={'id':identifier,'aliases':['CVE-2026-1000',*matched]})
    service=app.state.watch_service
    service.transport=httpx.MockTransport(respond)
    def run():
        with patch.object(service.executor,'submit'):
            response=post(client,f"/watches/{watch['id']}/check",{})
        assert response.status_code==200,response.text
        service.run(client.get('/api/me').json()['workspace'],response.json()['id'])
    run()
    first=data(client)['findings']
    assert len(first)==1 and len(data(client)['tasks'])==1
    identifier=first[0]['id']
    assert first[0]['matched_advisories']==matched
    assert client.get('/api/watches').json()['runs'][0]['advisory_details']['grouped_matches']==1
    matched[:]=['PYSEC-fixture-b']
    run()
    current=data(client)['findings']
    assert len(current)==1 and current[0]['id']==identifier
    assert len(data(client)['tasks'])==1 and len(client.get('/api/notifications').json()['notifications'])==1
    assert client.get('/api/watches').json()['runs'][0]['new_matches']==0
    # A different watch has its own asset/scope, even with identical aliases.
    watch=create(client,create_tasks=True)
    run()
    assert len(data(client)['findings'])==2 and len(data(client)['tasks'])==2
    assert len(client.get('/api/notifications').json()['notifications'])==2
