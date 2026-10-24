import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from backend.dependency_inventory import inventory,preview,MAX_BYTES
from backend import scanner
from test_platform import system,post,asset,data


def lock():
    return json.dumps({'lockfileVersion':3,'packages':{
        '':{'name':'private-root'},
        'node_modules/example':{'version':'1.2.3','resolved':'https://registry.npmjs.org/example/-/example-1.2.3.tgz'},
        'node_modules/parent/node_modules/example':{'version':'2.0.0','resolved':'https://registry.npmjs.org/example/-/example-2.0.0.tgz','optional':True},
        'node_modules/private':{'version':'1.0.0','resolved':'https://token:password@private.test/internal-path'},
        'node_modules/local':{'link':True,'resolved':'../../secret-path'},
    }})


def test_lock_variants_select_exact_subset_and_redact_sources():
    value=preview(lock(),'package-lock')
    assert [p['version'] for p in value['packages']]==['1.2.3','2.0.0']
    assert value['coverage']['root_records']==1 and value['coverage']['skipped_records']==2
    assert not any(secret in json.dumps(value) for secret in ['private-root','internal-path','token:password','secret-path'])
    selected=inventory(lock(),'package-lock',[value['packages'][1]['id']])
    assert selected['coverage']['excluded']==1 and selected['packages'][0]['version']=='2.0.0'
    with pytest.raises(ValueError):inventory(lock(),'package-lock',[['invalid']])
    with pytest.raises(ValueError):inventory(lock(),'package-lock',['not-in-source'])


def test_uv_universal_versions_private_sources_and_schema_are_explicit():
    source='''version = 1
revision = 3
[[package]]
name = "project-root"
version = "1.0"
source = { editable = "." }
[[package]]
name = "Example_Package"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "example-package"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "private-project"
version = "1.0"
source = { registry = "https://private.test/simple" }
'''
    result=inventory(source,'uv-lock')
    assert len(result['packages'])==2 and {p['name'] for p in result['packages']}=={'example-package'}
    assert result['coverage']['skipped_records']==1 and result['coverage']['root_records']==1
    assert 'private-project' not in json.dumps(result)
    with pytest.raises(ValueError):inventory(source.replace('revision = 3','revision = 99'),'uv-lock')


def test_duplicate_keys_oversized_inventory_and_requirements_conflicts_are_rejected():
    for source,format in [('{"packages":{},"packages":{},"lockfileVersion":3}','package-lock'),('a'*(MAX_BYTES+1),'requirements'),('Foo_Bar==1\nfoo-bar==2','requirements')]:
        with pytest.raises(ValueError):inventory(source,format)
    pins=[{'ecosystem':'npm','name':f'example{i}','version':'1.0.0'} for i in range(501)]
    with pytest.raises(ValueError):inventory(json.dumps({'packages':pins}),'exact-inventory')


def test_real_frontend_lockfile_fits_without_installing_or_contacting_registry():
    result=inventory((Path(__file__).parents[1]/'frontend/package-lock.json').read_text(encoding='utf-8'),'package-lock')
    assert 100<len(result['packages'])<=500 and not result['skipped']


def test_batches_keep_completed_coverage_when_later_provider_request_fails():
    packages=[{'ecosystem':'npm','name':f'example{i}','version':'1.0.0','line':0} for i in range(105)]
    calls=[]
    def provider(request):
        queries=json.loads(request.content)['queries'];calls.append(queries)
        if len(calls)==2:return httpx.Response(503)
        return httpx.Response(200,json={'results':[{} for _ in queries]})
    result=scanner.scan_watch(packages,httpx.MockTransport(provider))
    assert [len(q) for q in calls]==[50,50] and len(result['checked'])==50 and result['error']
    assert not result['findings']


def test_preview_never_calls_provider_and_new_import_requires_exact_approval(system):
    app,client,_=system
    with patch.object(scanner,'scan_watch',side_effect=AssertionError('Preview must not query OSV')):
        response=post(client,'/dependency-inventory/preview',{'content':lock(),'format':'package-lock'})
        assert response.status_code==200,response.text
        pin=response.json()['packages'][0]['id']
        body={'action':'dependencies','authorized':True,'format':'package-lock','content':lock()}
        assert post(client,'/operations',body).status_code==422
        assert post(client,'/operations',{**body,'dependency_selection':[pin]}).status_code==422
        assert not data(client)['operations']
    with patch.object(app.state.executor,'submit') as worker:
        response=post(client,'/operations',{**body,'dependency_selection':[pin],'dependency_consent':True})
        assert response.status_code==200,response.text
        assert worker.call_count==1


def test_watch_keeps_multiple_versions_without_raw_file_and_retains_coverage_gaps(system):
    app,client,_=system
    value=post(client,'/dependency-inventory/preview',{'content':lock(),'format':'package-lock'}).json()
    response=post(client,'/watches',{'name':'Lock scope','format':'package-lock','content':lock(),'consent':True,'dependency_selection':[p['id'] for p in value['packages']]})
    assert response.status_code==200,response.text
    watch=response.json()
    assert len(watch['packages'])==2 and 'content' not in watch and watch['dependency_inventory']['skipped_records']==2
    service=app.state.watch_service
    service.transport=httpx.MockTransport(lambda request:httpx.Response(200,json={'results':[{},{}]}))
    with patch.object(service.executor,'submit'):
        run=post(client,f"/watches/{watch['id']}/check",{}).json()
    service.run(client.get('/api/me').json()['workspace'],run['id'])
    run=client.get('/api/watches').json()['runs'][0]
    assert run['status']=='partial' and run['checked']==2 and run['dependency_inventory']['skipped_records']==2


def test_enlarged_dependency_routes_still_require_auth_csrf_and_bounded_source(system):
    _,client,_=system
    large='\n# padding'*20000+'\nexample==1.0.0'
    assert len(large)>160000
    assert post(client,'/dependency-inventory/preview',{'content':large,'format':'requirements'}).status_code==200
    assert client.post('/api/dependency-inventory/preview',json={'content':large,'format':'requirements'}).status_code==403
    assert post(client,'/dependency-inventory/preview',{'content':'x'*(MAX_BYTES+1),'format':'requirements'}).status_code==422
    client.cookies.clear()
    assert client.post('/api/dependency-inventory/preview',json={'content':large,'format':'requirements'}).status_code==401


def test_focused_scan_sends_only_selected_versions_and_persists_no_raw_source(system):
    _,client,_=system
    identifier=asset(client)['id']
    pins=post(client,'/dependency-inventory/preview',{'content':lock(),'format':'package-lock'}).json()['packages']
    body={'asset_id':identifier,'kind':'dependencies','label':'Approved lock scope','content':lock(),'format':'package-lock','authorized':True,'dependency_selection':[pins[1]['id']]}
    assert post(client,'/scans',body).status_code==422
    calls=[]
    def provider(request):
        calls.append(json.loads(request.content))
        return httpx.Response(200,json={'results':[{}]})
    original=scanner.scan_watch
    with patch.object(scanner,'scan_watch',side_effect=lambda packages,transport=None:original(packages,httpx.MockTransport(provider))):
        response=post(client,'/scans',{**body,'dependency_consent':True})
    assert response.status_code==200,response.text
    assert calls==[{'queries':[{'package':{'ecosystem':'npm','name':'example'},'version':'2.0.0'}]}]
    result=response.json()
    assert result['status']=='partial' and result['dependency_inventory']['excluded']==1 and len(result['checked'])==1
    assert not any(secret in json.dumps(data(client)) for secret in ['private-root','internal-path','token:password','secret-path'])
