import copy
import json
import sqlite3
import subprocess
from datetime import datetime,timezone,timedelta
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient
from backend.device_updates import Report,assessment
from backend import device_update_migration
from backend.store import Store,SCHEMA_VERSION
from companion import device_agent
from test_platform import system,post,data,PASSWORD
from test_operations import queue,execute


def report():
    return device_agent.collect_updates(lambda tool:{'pending':3,'security':2,'title':'private-title','id':'private-machine'} if tool=='cache' else {'required':True},'Windows')


def test_collector_sanitizes_counts_and_no_freshness_or_compliance_claim():
    value=report()
    assert value['cache']['pending']==3 and value['cache']['security']==2
    assert 'private-' not in json.dumps(value)
    result=assessment(value)
    assert {item['rule'] for item in result['findings']}=={'UPD001','UPD002'}
    assert 'zero cached updates does not mean fully patched' in result['limits'].lower()
    assert not result['error']


def test_zero_cache_is_only_a_cached_observation_and_partial_never_clean():
    value=device_agent.collect_updates(lambda tool:{'pending':0,'security':0} if tool=='cache' else {'required':False},'Windows')
    assert not assessment(value)['findings'] and 'freshness is unknown' in assessment(value)['limits']
    value=device_agent.collect_updates(lambda tool:{'error':'permission_denied'} if tool=='cache' else {'required':False},'Windows')
    assert value['cache']=={'state':'unassessed','reason':'permission_denied'}
    assert assessment(value)['error'] and not assessment(value)['findings']


@pytest.mark.parametrize('cache',[{'pending':True,'security':0},{'pending':2,'security':3},{'pending':-1,'security':0},{'pending':10001,'security':0},{'pending':0},{'pending':'2','security':1}])
def test_bad_provider_counts_stay_unassessed(cache):
    value=device_agent.collect_updates(lambda tool:cache if tool=='cache' else {'required':False},'Windows')
    assert value['cache']['state']=='unassessed'


def test_nonwindows_does_not_run_tools_and_parser_rejects_extra_raw_fields():
    with patch.object(device_agent,'update_command') as command:
        value=device_agent.collect_updates(command,'Linux')
    command.assert_not_called()
    assert assessment(value)['error']
    bad=report();bad['cache']['title']='must-not-store'
    with pytest.raises(ValidationError):Report.model_validate(bad)
    for update in [{'platform':'linux'},{'generated_at':(datetime.now(timezone.utc)-timedelta(days=1)).isoformat()},{'source':'online-live-catalog'},{'reboot':{'state':'observed','required':'yes'}},{'cache':{'state':'unassessed','reason':'timeout','pending':0}}]:
        with pytest.raises(ValidationError):Report.model_validate({**report(),**update})


def test_fixed_update_tools_never_request_online_catalog_install_or_reboot(tmp_path,monkeypatch):
    executable=tmp_path/'System32/WindowsPowerShell/v1.0/powershell.exe';executable.parent.mkdir(parents=True);executable.write_bytes(b'fixture-not-executable')
    monkeypatch.setenv('SystemRoot',str(tmp_path))
    def run(arguments,**kwargs):
        assert arguments[0]==str(executable) and kwargs['shell'] is False and kwargs['timeout']==35
        assert kwargs['stdin']==subprocess.DEVNULL
        script=arguments[-1]
        assert '$searcher.Online=$false' in script and "Type='Software'" in script and '$count -gt 10000' in script
        assert 'CreateUpdateInstaller' not in script and 'CreateUpdateDownloader' not in script and 'Restart-Computer' not in script
        return SimpleNamespace(returncode=0,stdout=b'{"pending":2,"security":1}')
    with patch.object(device_agent.subprocess,'run',side_effect=run):
        assert device_agent.update_command('cache')['pending']==2
        with pytest.raises(ValueError):device_agent.update_command('cache; injected')
    with patch.object(device_agent.subprocess,'run',side_effect=subprocess.TimeoutExpired('fixed',35)):
        assert device_agent.update_command('reboot')=={'error':'timeout'}


def test_local_update_job_and_separate_paired_permission_and_protocol(system,monkeypatch):
    app,client,_=system
    operation,body=queue(app,client,monkeypatch,action='updates')
    with patch.object(device_agent,'collect_updates',return_value=report()),patch.object(device_agent.socket,'create_connection') as socket:
        result=execute(app,client,operation,body)
    socket.assert_not_called();assert result['status']=='complete'
    assert data(client)['scans'][0]['kind']=='updates'
    assert post(client,'/operations',{'action':'updates','target':'192.168.1.10','authorized':True}).status_code==422
    app.state.settings.secure=True
    assert post(client,'/operations',{'action':'updates','authorized':True}).status_code==409
    grant=post(client,'/device-connections',{'label':'Posture only','password':PASSWORD,'allow_posture':True}).json()
    assert not grant['allow_updates']
    assert post(client,'/operations',{'action':'updates','device_id':grant['id'],'authorized':True}).status_code==409
    grant=post(client,'/device-connections',{'label':'Updates opted in','password':PASSWORD,'allow_updates':True}).json()
    worker=TestClient(app);headers={'Authorization':'Bearer '+grant['token']}
    for heartbeat in [{},{'version':2,'posture_enabled':True},{'version':3,'updates_enabled':False}]:
        operation=post(client,'/operations',{'action':'updates','device_id':grant['id'],'authorized':True}).json()
        response=worker.post('/api/device-agent/poll',json=heartbeat,headers=headers)
        assert response.json()['operation'] is None
        assert next(o for o in data(client)['operations'] if o['id']==operation['id'])['status']=='failed'
    operation=post(client,'/operations',{'action':'updates','device_id':grant['id'],'authorized':True}).json()
    lease=worker.post('/api/device-agent/poll',json={'version':3,'updates_enabled':True},headers=headers).json()['operation']
    assert lease['action']=='updates' and lease['ports']==[]
    body={'operation_id':operation['id'],'lease':lease['lease'],'observations':[]}
    assert worker.post('/api/device-agent/result',json=body,headers=headers).status_code==422
    assert worker.post('/api/device-agent/result',json={**body,'updates':report(),'observations':[{'host':'127.0.0.1','port':22,'status':'open'}]},headers=headers).status_code==422
    assert worker.post('/api/device-agent/result',json={**body,'updates':report()},headers=headers).status_code==200
    assert worker.post('/api/device-agent/result',json={**body,'updates':report()},headers=headers).status_code==409
    assert data(client)['audit']['valid']


def test_agent_requires_both_consents_and_never_collects_after_scope_failure():
    config={'allowed_targets':['127.0.0.1'],'allow_updates':True}
    job={'id':'fixture-job','action':'updates','target':'127.0.0.1','ports':[],'lease':'fixture-lease-'*4}
    calls=[]
    def requester(config,path,body):
        calls.append((path,body));return {'operation':job} if path.endswith('/poll') else {'ok':True}
    with patch.object(device_agent,'collect_updates',return_value=report()) as collect,patch.object(device_agent.socket,'create_connection') as socket:
        with pytest.raises(ValueError):device_agent.poll_once(config,requester)
        with pytest.raises(ValueError):device_agent.poll_once({**config,'allow_updates':False},requester,allow_updates=True)
        collect.assert_not_called()
        assert device_agent.poll_once(config,requester,allow_updates=True)
        job['target']='192.168.1.10'
        with pytest.raises(ValueError):device_agent.poll_once(config,requester,allow_updates=True)
        assert collect.call_count==1
    socket.assert_not_called()
    assert any(body.get('version')==3 and body['updates_enabled'] for path,body in calls if path.endswith('/poll'))
    assert len([body for path,body in calls if path.endswith('/result')])==1


def test_update_payload_is_refused_for_plain_tcp_job(system,monkeypatch):
    app,client,_=system
    grant=post(client,'/device-connections',{'label':'TCP only','password':PASSWORD}).json()
    operation=post(client,'/operations',{'action':'device','ports':[22],'device_id':grant['id'],'authorized':True}).json()
    worker=TestClient(app);headers={'Authorization':'Bearer '+grant['token']}
    lease=worker.post('/api/device-agent/poll',json={'version':3,'updates_enabled':True},headers=headers).json()['operation']
    response=worker.post('/api/device-agent/result',json={'operation_id':operation['id'],'lease':lease['lease'],'observations':[{'host':'127.0.0.1','port':22,'status':'closed'}],'updates':report()},headers=headers)
    assert response.status_code==422


def test_version_ten_migration_preserves_existing_device_and_never_grants_new_access(tmp_path):
    path=tmp_path/'old.db';store=Store(path)
    with store.connect(write=True) as c:
        c.execute('ALTER TABLE devices DROP COLUMN allow_updates');c.execute('ALTER TABLE devices DROP COLUMN updates_enabled');c.execute('DELETE FROM schema_migrations WHERE version>=10');c.execute('DROP TABLE client_vaults');c.execute('DROP TABLE clients');c.execute('DROP TABLE workflow_steps');c.execute('DROP TABLE workflows')
        c.execute('INSERT INTO devices(id,token,workspace,user,label,targets,expires,allow_posture) VALUES(?,?,?,?,?,?,?,?)',('device','secret-hash','space','user','Existing','["127.0.0.1"]',9999999999,1))
    for _ in range(2):
        with Store(path).connect() as c:
            row=c.execute('SELECT * FROM devices').fetchone()
            assert row['token']=='secret-hash' and row['allow_posture']==1 and row['allow_updates']==row['updates_enabled']==0
            assert c.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0]==SCHEMA_VERSION
    with store.connect(write=True) as c:c.execute('ALTER TABLE devices DROP COLUMN updates_enabled')
    with pytest.raises(ValueError,match='incomplete'):Store(path)


def test_combined_review_update_observations_feed_one_approved_agent_job(system):
    from test_platform import workflow_provider
    app,client,_=system
    app.state.settings.groq_key='fixture-only';app.state.agent_transport=workflow_provider()
    with patch.object(app.state.executor,'submit') as submit:
        response=post(client,'/security-reviews',dict(workspace_id=client.get('/api/me').json()['workspace'],name='Update workflow',authorized=True,ai_triage=True,checks=[dict(action='updates',authorized=True)]))
    assert response.status_code==200,response.text
    arguments=submit.call_args.args
    with patch.object(device_agent,'collect_updates',return_value=report()):arguments[0](*arguments[1:])
    value=data(client)
    assert value['security_reviews'][0]['status']=='complete'
    assert value['jobs'][0]['status']=='complete' and len(value['tasks'])==2
    assert value['scans'][0]['updates']['source']=='windows-update-offline-cache'


def test_update_migration_rolls_back_columns_and_marker_on_validation_failure(tmp_path,monkeypatch):
    path=tmp_path/'rollback.db';store=Store(path)
    with store.connect(write=True) as c:
        c.execute('ALTER TABLE devices DROP COLUMN allow_updates');c.execute('ALTER TABLE devices DROP COLUMN updates_enabled');c.execute('DELETE FROM schema_migrations WHERE version>=10');c.execute('DROP TABLE client_vaults');c.execute('DROP TABLE clients');c.execute('DROP TABLE workflow_steps');c.execute('DROP TABLE workflows')
    def fail(c):raise RuntimeError('simulated migration validation failure')
    monkeypatch.setattr(device_update_migration,'validate_layout',fail)
    with pytest.raises(RuntimeError):Store(path)
    with store.connect() as c:
        assert not set(device_update_migration.COLUMNS).intersection(row[1] for row in c.execute('PRAGMA table_info(devices)'))
        assert c.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0]==9
