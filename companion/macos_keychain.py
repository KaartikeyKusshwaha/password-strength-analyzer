"""Exact-service macOS Keychain storage. Secrets never enter argv, files or logs."""
import json
import platform
import secrets
import tempfile
from pathlib import Path
from contextlib import contextmanager
from companion.helper_client import CLOUD_ORIGIN
from companion.device_agent import validate_connection

SERVICE='org.sentinelops.devicehelper.connection'
ACCOUNT='paired-device-v1'

def scoped(value):
    value=validate_connection(value)
    if set(value)-{'server','token','allowed_targets','allow_posture','allow_updates','id'}:raise ValueError('Unexpected helper connection fields.')
    if value['server']!=CLOUD_ORIGIN or value['allowed_targets']!=['127.0.0.1','::1']:
        raise ValueError('Unexpected helper scope.')
    return value

class KeychainStore:
    def __init__(self,security=None,service=SERVICE,keychain=None):
        if service!=SERVICE and not service.startswith(SERVICE+'.test-'):raise ValueError('Unsupported keychain service.')
        if security is None:
            if platform.system()!='Darwin':raise ValueError('macOS Keychain is required.')
            import Security
            security=Security
        self.api=security;self.service=service;self.keychain=keychain
    def query(self,add=False):
        api=self.api
        value={api.kSecClass:api.kSecClassGenericPassword,api.kSecAttrService:self.service,api.kSecAttrAccount:ACCOUNT,api.kSecAttrSynchronizable:False}
        if self.keychain is not None:value[api.kSecUseKeychain if add else api.kSecMatchSearchList]=self.keychain if add else [self.keychain]
        return value
    def save(self,value):
        raw=json.dumps(scoped(value),separators=(',',':')).encode()
        if len(raw)>12000:raise ValueError('Device connection is too large.')
        api=self.api;status,_=api.SecItemAdd({**self.query(add=True),api.kSecValueData:raw},None)
        if status==api.errSecDuplicateItem:status=api.SecItemUpdate(self.query(),{api.kSecValueData:raw})
        if status!=api.errSecSuccess:raise ValueError('Keychain did not save the device connection (OSStatus '+str(status)+'). Unlock the login keychain and retry; no plaintext copy was saved.')
    def load(self):
        api=self.api
        query={**self.query(),api.kSecReturnData:True,api.kSecMatchLimit:api.kSecMatchLimitOne,api.kSecUseAuthenticationUI:api.kSecUseAuthenticationUIFail}
        status,raw=api.SecItemCopyMatching(query,None)
        if status==api.errSecItemNotFound:return None
        if status!=api.errSecSuccess:raise ValueError('Keychain is locked, access was denied or authorization is required. Open Keychain Access and reconnect; no substitute connection was loaded.')
        try:
            raw=bytes(raw)
            if len(raw)>12000:raise ValueError()
            return scoped(json.loads(raw))
        except (ValueError,TypeError,KeyError):raise ValueError('The protected device connection is invalid. Reconnect this helper.') from None
    def delete(self):
        api=self.api;status=api.SecItemDelete(self.query())
        if status not in {api.errSecSuccess,api.errSecItemNotFound}:raise ValueError('Keychain did not remove this helper connection. Revoke its server connection in the extension.')

@contextmanager
def disposable_keychain():
    """Native smoke tests only; never changes the user's default/search-list keychains."""
    if platform.system()!='Darwin':raise ValueError('Native macOS verification required.')
    import Security
    with tempfile.TemporaryDirectory(prefix='sentinelops-keychain-test-') as folder:
        path=Path(folder)/'verification.keychain-db';password=secrets.token_bytes(32)
        status,keychain=Security.SecKeychainCreate(str(path).encode(),len(password),password,False,None,None)
        if status!=Security.errSecSuccess:raise ValueError('Disposable Keychain creation failed (OSStatus '+str(status)+').')
        try:yield Security,keychain
        finally:
            if not path.resolve().is_relative_to(Path(folder).resolve()):raise ValueError('Refusing Keychain cleanup outside its test folder.')
            if Security.SecKeychainDelete(keychain)!=Security.errSecSuccess:raise ValueError('Disposable Keychain cleanup failed.')
