import copy
import json
import subprocess
from datetime import datetime,timezone,timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from companion import device_agent
from backend.posture import Report,assessment
from test_platform import PASSWORD,system,post,data
from test_operations import queue,execute


def native_values(tool):
    return {'firewall':[{'Name':name,'Enabled':True} for name in ('Domain','Private','Public')], 'defender':{'AntivirusEnabled':True,'RealTimeProtectionEnabled':True,'AMRunningMode':'Normal'},'system_disk':{'ProtectionStatus':1,'ReturnValue':0,'KeyProtector':'fixture-secret-never-export'}}[tool]


def report(state='enabled'):
    return {'version':1,'platform':'windows','generated_at':datetime.now(timezone.utc).isoformat(),'checks':[{'id':key,'state':state,'reason':''} for key in device_agent.POSTURE_CHECKS]}


def test_readonly_collection_emits_only_fixed_states_not_raw_provider_properties():
    result=device_agent.collect_posture(native_values,'Windows')
    assert all(check['state']=='enabled' for check in result['checks'])
    assert 'KeyProtector' not in json.dumps(result) and 'fixture-secret' not in json.dumps(result)
    assert assessment(result)['findings']==[]
    assert assessment(result)['error'] is None


def test_passive_defender_is_not_misreported_as_absent_antivirus_and_partial_coverage_is_explicit():
    def runner(tool):
        if tool=='firewall':return {'error':'permission_denied'}
        if tool=='defender':return {'AntivirusEnabled':False,'RealTimeProtectionEnabled':False,'AMRunningMode':'Passive Mode'}
        return {'error':'timeout'}
    value=device_agent.collect_posture(runner,'Windows')
    assert next(item for item in value['checks'] if item['id']=='defender')['state']=='passive'
    assert assessment(value)['error'] and assessment(value)['findings']==[]
    assert {item['reason'] for item in value['checks']}=={'permission_denied','','timeout'}


def test_non_windows_never_executes_windows_commands_or_reports_a_clean_assessment():
    with patch.object(device_agent,'posture_command') as command:
        value=device_agent.collect_posture(command,'Linux')
    command.assert_not_called()
    assert all(item['state']=='unsupported' for item in value['checks'])
    assert assessment(value)['error'] and not assessment(value)['findings']


def test_fixed_tool_execution_has_no_external_arguments_shell_profile_or_elevation(tmp_path,monkeypatch):
    executable=tmp_path/'System32/WindowsPowerShell/v1.0/powershell.exe';executable.parent.mkdir(parents=True);executable.write_bytes(b'fixture-not-executable')
    monkeypatch.setenv('SystemRoot',str(tmp_path))
    def run(arguments,**kwargs):
        assert arguments[0]==str(executable) and arguments[1:5]==['-NoLogo','-NoProfile','-NonInteractive','-Command']
        assert kwargs['shell'] is False and kwargs['timeout']==15 and kwargs['stdin']==subprocess.DEVNULL
        assert 'Invoke-CimMethod -MethodName GetProtectionStatus' in arguments[5] and 'Select-Object ProtectionStatus,ReturnValue' in arguments[5]
        assert 'KeyProtector' not in arguments[5] and 'Set-' not in arguments[5] and 'RunAs' not in arguments[5]
        return SimpleNamespace(returncode=0,stdout=b'{"ProtectionStatus":1,"ReturnValue":0}')
    with patch.object(device_agent.subprocess,'run',side_effect=run) as command:
        assert device_agent.posture_command('system_disk')=={'ProtectionStatus':1,'ReturnValue':0}
        with pytest.raises(ValueError):device_agent.posture_command('system_disk; malicious-job-input')
        assert command.call_count==1
    with patch.object(device_agent.subprocess,'run',side_effect=subprocess.TimeoutExpired('fixed-tool',15)):
        assert device_agent.posture_command('defender')=={'error':'timeout'}
    with patch.object(device_agent.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'private fixture error text, not JSON')):
        assert device_agent.posture_command('defender')=={'error':'invalid_response'}


def test_report_bounds_and_platform_semantics_reject_extra_fields_duplicate_ids_and_stale_times():
    value=report()
    for change in [{'platform':'linux'},{'checks':value['checks'][:-1]+[value['checks'][0]]},{'generated_at':(datetime.now(timezone.utc)-timedelta(days=1)).isoformat()},{'recovery_key':'never-return-this'},{'checks':[{**item,'state':'passive'} for item in value['checks']]}]:
        with pytest.raises(ValidationError):Report.model_validate({**value,**change})
    bad=copy.deepcopy(value);bad['checks'][0].update(state='unassessed',reason='')
    with pytest.raises(ValidationError):Report.model_validate(bad)


def test_unknown_or_failed_bitlocker_status_never_becomes_enabled():
    for disk in [{'ProtectionStatus':1,'ReturnValue':5},{'ProtectionStatus':1},{'ProtectionStatus':2,'ReturnValue':0}]:
        value=device_agent.collect_posture(lambda tool:disk if tool=='system_disk' else native_values(tool),'Windows')
        check=next(item for item in value['checks'] if item['id']=='system_disk')
        assert check['state']=='unassessed' and assessment(value)['error']


def test_local_posture_job_persists_separate_profile_findings_without_any_network_probe(system,monkeypatch):
    app,client,_=system
    operation,body=queue(app,client,monkeypatch,action='posture')
    with patch.object(device_agent,'collect_posture',return_value=report('disabled')),patch.object(device_agent.socket,'create_connection') as network:
        result=execute(app,client,operation,body)
    network.assert_not_called()
    assert result['status']=='complete'
    current=data(client);assert len(current['findings'])==5 and len({f['fingerprint'] for f in current['findings']})==5
    assert current['scans'][0]['kind']=='posture' and current['scans'][0]['observations']==[]
    assert current['scans'][0]['posture']['platform']=='windows'


def test_posture_is_only_the_operator_host_and_hosted_service_requires_pairing(system):
    app,client,_=system
    assert post(client,'/operations',{'action':'posture','target':'192.168.1.10','authorized':True}).status_code==422
    app.state.settings.secure=True
    assert post(client,'/operations',{'action':'posture','authorized':True}).status_code==409


def test_remote_posture_requires_pairing_opt_in_and_a_matching_typed_report(system):
    app,client,_=system
    body={'label':'Fixture posture agent','password':PASSWORD,'targets':['127.0.0.1']}
    old=post(client,'/device-connections',body).json()
    assert not old['allow_posture']
    assert post(client,'/operations',{'action':'posture','device_id':old['id'],'authorized':True}).status_code==409
    grant=post(client,'/device-connections',{**body,'allow_posture':True}).json()
    operation=post(client,'/operations',{'action':'posture','device_id':grant['id'],'authorized':True}).json()
    worker=TestClient(app);headers={'Authorization':'Bearer '+grant['token']}
    leased=worker.post('/api/device-agent/poll',json={'version':2,'posture_enabled':True},headers=headers).json()['operation']
    assert leased['action']=='posture' and leased['ports']==[]
    result={'operation_id':operation['id'],'lease':leased['lease'],'observations':[]}
    assert worker.post('/api/device-agent/result',json=result,headers=headers).status_code==422
    assert worker.post('/api/device-agent/result',json={**result,'observations':[{'host':'127.0.0.1','port':22,'status':'open'}],'posture':report()},headers=headers).status_code==422
    assert worker.post('/api/device-agent/result',json={**result,'posture':report()},headers=headers).status_code==200
    current=data(client)
    assert current['scans'][0]['kind']=='posture' and current['scans'][0]['posture']['checks'][0]['state']=='enabled'
    assert current['devices'][-1]['allow_posture'] or current['devices'][0]['allow_posture']


def test_client_enforces_both_local_and_server_consent_before_collecting_or_uploading():
    config={'allowed_targets':['127.0.0.1'],'allow_posture':True}
    job={'id':'fixture-job','action':'posture','target':'127.0.0.1','ports':[],'lease':'fixture-lease-'*4}
    calls=[]
    def request(config,path,body):
        calls.append((path,body));return {'operation':job} if path.endswith('/poll') else {'ok':True}
    with patch.object(device_agent,'collect_posture',return_value=report()) as collect,patch.object(device_agent.socket,'create_connection') as network:
        with pytest.raises(ValueError):device_agent.poll_once(config,request)
        with pytest.raises(ValueError):device_agent.poll_once({**config,'allow_posture':False},request,True)
        assert not collect.called
        assert device_agent.poll_once(config,request,True)
        assert collect.call_count==1
        job['target']='192.168.1.10'
        with pytest.raises(ValueError):device_agent.poll_once(config,request,True)
    network.assert_not_called()
    uploaded=[body for path,body in calls if path.endswith('/result')]
    assert len(uploaded)==1 and uploaded[0]['observations']==[] and uploaded[0]['posture']['version']==1


def test_device_schema_upgrade_does_not_expand_existing_connection_consent(tmp_path):
    import sqlite3
    from backend.store import Store
    path=tmp_path/'v6.db'
    with sqlite3.connect(path) as c:
        c.execute('CREATE TABLE devices(id TEXT PRIMARY KEY,token TEXT UNIQUE NOT NULL,workspace TEXT NOT NULL,user TEXT NOT NULL,label TEXT NOT NULL,targets TEXT NOT NULL,expires REAL NOT NULL,seen REAL)')
        c.execute('INSERT INTO devices VALUES(?,?,?,?,?,?,?,?)',('fixture','hashed-fixture','workspace','user','Ports only','["127.0.0.1"]',9999999999,None))
    with Store(path).connect() as c:
        row=c.execute('SELECT * FROM devices').fetchone()
        assert row['allow_posture']==0 and row['token']=='hashed-fixture'
        assert row['protocol_version']==1 and row['posture_enabled']==0


def test_old_or_locally_unconsented_client_fails_posture_job_without_dispatch(system):
    app,client,_=system
    grant=post(client,'/device-connections',{'label':'Fixture client','password':PASSWORD,'allow_posture':True}).json()
    worker=TestClient(app);headers={'Authorization':'Bearer '+grant['token']}
    for heartbeat in [{},{'version':2,'posture_enabled':False}]:
        response=post(client,'/operations',{'action':'posture','device_id':grant['id'],'authorized':True})
        assert response.status_code==200,response.text
        result=worker.post('/api/device-agent/poll',json=heartbeat,headers=headers)
        assert result.json()['operation'] is None
        job=next(o for o in data(client)['operations'] if o['id']==response.json()['id'])
        assert job['status']=='failed' and '--allow-posture' in job['error']
