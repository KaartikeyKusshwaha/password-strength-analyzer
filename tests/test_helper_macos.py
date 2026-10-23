import json
import platform
import plistlib
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from companion import helper_macos,macos_posture,device_agent
from companion.macos_keychain import KeychainStore,SERVICE,ACCOUNT
from companion.helper_client import CLOUD_ORIGIN
from test_platform import system

def config():return {'server':CLOUD_ORIGIN,'token':'x'*54,'allowed_targets':['127.0.0.1','::1'],'allow_posture':True,'allow_updates':False}

class SecurityFake:
    kSecClass='class';kSecClassGenericPassword='generic';kSecAttrService='service';kSecAttrAccount='account';kSecAttrSynchronizable='sync';kSecValueData='data';kSecReturnData='return';kSecMatchLimit='limit';kSecMatchLimitOne='one';kSecUseAuthenticationUI='ui';kSecUseAuthenticationUIFail='fail';kSecUseKeychain='keychain';kSecMatchSearchList='search'
    errSecSuccess=0;errSecDuplicateItem=-25299;errSecItemNotFound=-25300
    def __init__(self):self.saved=None;self.calls=[];self.failure=None
    def check(self,q):
        assert q['class']=='generic' and q['service']==SERVICE and q['account']==ACCOUNT and q['sync'] is False
        self.calls.append(dict(q))
    def SecItemAdd(self,q,_):
        self.check(q)
        if self.failure:return self.failure,None
        if self.saved is not None:return self.errSecDuplicateItem,None
        self.saved=q['data'];return 0,None
    def SecItemUpdate(self,q,values):
        self.check(q)
        if self.failure:return self.failure
        self.saved=values['data'];return 0
    def SecItemCopyMatching(self,q,_):
        self.check(q);assert q['ui']=='fail' and q['return'] is True and q['limit']=='one'
        return (self.failure,None) if self.failure else (self.errSecItemNotFound,None) if self.saved is None else (0,self.saved)
    def SecItemDelete(self,q):
        self.check(q);self.saved=None;return 0

def test_keychain_add_update_load_delete_exact_scope_and_no_plaintext_fallback(tmp_path):
    api=SecurityFake();store=KeychainStore(api)
    assert store.load() is None;store.save(config());assert store.load()==config()
    updated={**config(),'token':'y'*54};store.save(updated);assert store.load()==updated
    store.delete();assert store.load() is None
    api.failure=-25293
    with pytest.raises(ValueError,match='no plaintext'):store.save(config())
    with pytest.raises(ValueError,match='locked'):store.load()
    assert not list(tmp_path.iterdir())

def test_keychain_rejects_extra_fields_wrong_origin_targets_and_invalid_saved_bytes():
    api=SecurityFake();store=KeychainStore(api)
    for value in [{**config(),'server':'https://other.example'},{**config(),'allowed_targets':['192.168.1.1']},{**config(),'password':'never-store-account-password'}]:
        with pytest.raises(ValueError):store.save(value)
    assert not api.calls
    api.saved=b'not-json'
    with pytest.raises(ValueError,match='invalid'):store.load()
    adapter=helper_macos.MacAdapter(store)
    with pytest.raises(ValueError,match='unsupported'):adapter.save({**config(),'allow_updates':True})
    assert not adapter.supports_updates

def bundle(root):
    app=root/helper_macos.APP;(app/'Contents/MacOS').mkdir(parents=True)
    (app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':helper_macos.BUNDLE}))
    (app/'Contents/MacOS/helper').write_bytes(b'fixture app, never executed')
    return app

def test_installer_is_per_user_exclusive_and_never_replaces_existing_app(tmp_path,monkeypatch):
    monkeypatch.setattr(helper_macos.platform,'system',lambda:'Darwin')
    source=bundle(tmp_path/'build');home=tmp_path/'home';home.mkdir()
    target=helper_macos.install(source,home)
    assert target==home/'Applications'/helper_macos.APP and helper_macos.checked_bundle(target)==target.resolve()
    assert helper_macos.install(target,home)==target
    with pytest.raises(ValueError,match='already installed'):helper_macos.install(source,home)
    assert (target/'Contents/MacOS/helper').read_bytes()==b'fixture app, never executed'
    assert not list((home/'Applications').glob('.sentinelops-install-*'))

def test_install_failure_or_racing_destination_keeps_existing_data(tmp_path,monkeypatch):
    monkeypatch.setattr(helper_macos.platform,'system',lambda:'Darwin')
    source=bundle(tmp_path/'build');home=tmp_path/'home';home.mkdir();original=helper_macos.shutil.copytree
    def race(copy_source,staging,*args,**kwargs):
        result=original(copy_source,staging,*args,**kwargs)
        if Path(copy_source).resolve()==source.resolve():
            other=home/'Applications'/helper_macos.APP;other.mkdir();(other/'private.txt').write_text('preserve me')
        return result
    monkeypatch.setattr(helper_macos.shutil,'copytree',race)
    with pytest.raises(FileExistsError):helper_macos.install(source,home)
    assert (home/'Applications'/helper_macos.APP/'private.txt').read_text()=='preserve me'
    assert not list((home/'Applications').glob('.sentinelops-install-*'))

def test_installer_refuses_wrong_bundle_and_non_mac_without_creating_files(tmp_path):
    app=bundle(tmp_path/'build');(app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'other.app'}))
    with pytest.raises(ValueError):helper_macos.checked_bundle(app)
    with patch.object(helper_macos.platform,'system',return_value='Windows'):
        with pytest.raises(ValueError,match='Mac'):helper_macos.install(app,tmp_path)
    assert not (tmp_path/'Applications').exists()

@pytest.mark.parametrize('tool,output,code,state',[
 ('application_firewall','Firewall is enabled. (State = 1)',0,'enabled'),
 ('application_firewall','Firewall is disabled. (State = 0)',0,'disabled'),
 ('filevault','FileVault is On.',0,'enabled'),('filevault','FileVault is Off.',0,'disabled'),
 ('gatekeeper','assessments enabled',0,'enabled'),('gatekeeper','assessments disabled',1,'disabled')])
def test_fixed_native_commands_parse_only_known_statuses(tool,output,code,state):
    def execute(argv,**kwargs):
        assert argv==list(macos_posture.TOOLS[tool]);assert kwargs['shell'] is False and kwargs['stdin']==subprocess.DEVNULL and kwargs['timeout']==12
        assert kwargs['env']['LC_ALL']=='C' and not any('password' in arg or 'sudo' in arg for arg in argv)
        return SimpleNamespace(returncode=code,stdout=output.encode(),stderr=b'')
    with patch.object(macos_posture.platform,'system',return_value='Darwin'),patch.object(macos_posture.subprocess,'run',side_effect=execute):
        assert macos_posture.command(tool)=={'state':state}

def test_malformed_localized_failed_or_timed_out_tools_never_become_enabled():
    with patch.object(macos_posture.platform,'system',return_value='Darwin'):
        for output in ['FileVault is On.\nEncryption in progress.','secret provider output','']:
            with patch.object(macos_posture.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=output.encode(),stderr=b'')):
                assert 'state' not in macos_posture.command('filevault')
        with patch.object(macos_posture.subprocess,'run',side_effect=subprocess.TimeoutExpired('fixed',12)):
            assert macos_posture.command('gatekeeper')=={'error':'timeout'}
        with patch.object(macos_posture.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout=b'assessments enabled',stderr=b'provider error')):
            assert 'state' not in macos_posture.command('gatekeeper')
    with pytest.raises(ValueError):macos_posture.command('filevault; rm -rf anything')
    report=macos_posture.collect(lambda tool:{'state':'disabled'} if tool=='filevault' else {'error':'permission_denied'})
    assert report['version']==2 and len(report['checks'])==3 and 'raw' not in json.dumps(report)
    with patch('companion.macos_posture.collect',return_value=report),patch.object(device_agent,'posture_command') as windows:
        assert device_agent.collect_posture(system='Darwin')==report;windows.assert_not_called()

def test_macos_schema_and_paired_result_reach_extension_as_states_not_windows_findings(system):
    from fastapi.testclient import TestClient
    from backend.posture import Report,assessment
    from test_platform import PASSWORD,post,data
    from test_device_pairing import access
    app,owner,_=system
    value=macos_posture.collect(lambda tool:{'state':'disabled' if tool=='filevault' else 'enabled'})
    assert Report.model_validate(value).version==2 and not assessment(value)['findings']
    connection=post(owner,'/device-connections',{'label':'Fixture Mac helper','password':PASSWORD,'targets':['127.0.0.1'],'allow_posture':True}).json()
    operation=post(owner,'/operations',{'action':'posture','device_id':connection['id'],'authorized':True}).json()
    worker=TestClient(app);headers={'Authorization':'Bearer '+connection['token']}
    leased=worker.post('/api/device-agent/poll',headers=headers,json={'version':3,'posture_enabled':True,'updates_enabled':False}).json()['operation']
    result=worker.post('/api/device-agent/result',headers=headers,json={'operation_id':operation['id'],'lease':leased['lease'],'observations':[],'posture':value})
    assert result.status_code==200,result.text
    assert data(owner)['scans'][0]['posture']==value
    extension,auth=access(app,owner)
    projected=extension.get('/api/companion/security/operations/'+operation['id'],headers=auth).json()
    assert projected['finding_count']==0 and len(projected['posture_checks'])==3
    assert next(r for r in projected['posture_checks'] if r['id']=='filevault')['state']=='disabled'
    assert 'Windows' not in projected['coverage'] and 'self-report' in projected['coverage']

def test_frozen_macos_transport_requires_certificate_and_hostname_verification():
    import ssl
    import sys
    with patch.object(device_agent.platform,'system',return_value='Darwin'),patch.object(sys,'frozen',True,create=True):
        context=device_agent.transport_context()
    assert context.verify_mode==ssl.CERT_REQUIRED and context.check_hostname

@pytest.mark.skipif(platform.system()!='Darwin',reason='Native macOS Keychain verification requires a Mac')
def test_real_native_keychain_roundtrip_in_disposable_keychain(tmp_path):
    helper_macos.self_test(tmp_path/'native-result.json')
    result=json.loads((tmp_path/'native-result.json').read_text())
    assert result['keychain_roundtrip'] and result['keychain_test_item_removed'] and result['storage_scope']=='disposable-keychain-native-api'
    assert 'token' not in result
