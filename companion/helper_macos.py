"""Per-user macOS app installer, existing pairing/poller and Keychain adapter."""
import json
import platform
import plistlib
import secrets
import shutil
import ssl
import sys
import uuid
from pathlib import Path
from companion.helper_client import VERSION,CLOUD_ORIGIN
from companion.macos_keychain import KeychainStore,SERVICE,disposable_keychain

APP='SentinelOpsDeviceHelper.app'
BUNDLE='org.sentinelops.devicehelper'

def checked_bundle(path):
    path=Path(path)
    if path.is_symlink() or not path.is_dir() or path.name!=APP or {p.name for p in path.iterdir()}!={'Contents'}:raise ValueError('Use the packaged SentinelOps macOS application.')
    info=path/'Contents/Info.plist'
    if info.is_symlink() or plistlib.loads(info.read_bytes()).get('CFBundleIdentifier')!=BUNDLE:raise ValueError('Unexpected application bundle identity.')
    resolved=path.resolve()
    if any(p.is_symlink() and not p.resolve().is_relative_to(resolved) for p in path.rglob('*')):raise ValueError('Application contains links outside its bundle.')
    return resolved

def install(source=None,home=None):
    if platform.system()!='Darwin':raise ValueError('Install the macOS helper on a Mac.')
    if source is None:
        if not getattr(sys,'frozen',False):raise ValueError('Use the packaged macOS helper application.')
        source=Path(sys.executable).parents[2]
    source=checked_bundle(source)
    home=Path(home or Path.home())
    if not home.is_absolute() or home.is_symlink():raise ValueError('User home folder unavailable.')
    apps=home/'Applications'
    if apps.is_symlink():raise ValueError('Linked Applications folders are unsupported.')
    apps.mkdir(parents=True,exist_ok=True);apps=apps.resolve();target=apps/APP
    if target.exists() or target.is_symlink():
        if checked_bundle(target)==source:return target
        raise ValueError('A helper is already installed. Close it and move that application to Trash before installing this version. Its Keychain connection is separate.')
    staging=apps/('.sentinelops-install-'+uuid.uuid4().hex+'.app')
    try:
        shutil.copytree(source,staging,symlinks=True)
        # Exclusive creation prevents POSIX rename from replacing even an empty
        # app directory that appeared after the initial existence check.
        target.mkdir(mode=0o755)
        try:(staging/'Contents').rename(target/'Contents')
        except BaseException:
            try:target.rmdir() # Only our still-empty directory, never a tree.
            except OSError:pass
            raise
    finally:
        if staging.exists():
            if staging.parent!=apps or not staging.resolve().is_relative_to(apps) or staging.is_symlink():raise ValueError('Staging cleanup refused outside the application folder.')
            shutil.rmtree(staging)
    return target

class MacAdapter:
    platform_name='macOS'
    supports_updates=False
    posture_label='Allow read-only application-firewall, FileVault and Gatekeeper status'
    updates_label='Windows cached-update check is unavailable on macOS'
    initial_status='Install for this Mac user and connect from the browser extension.'
    storage_note='Installed under your Applications folder. Device connection stays in your macOS login Keychain, not a plaintext file. No launch agent or startup service. Revoke the cloud connection in SentinelOps. Stop the helper and move its app to Trash to uninstall; forget the local connection first if desired.'
    def __init__(self,store=None):self.store=store or KeychainStore()
    def install(self):return install()
    def load(self):
        value=self.store.load()
        if value and value.get('allow_updates'):raise ValueError('macOS cached-update permission is unsupported. Reconnect this helper.')
        return value
    def save(self,value):
        if value.get('allow_updates'):raise ValueError('macOS cached-update permission is unsupported.')
        self.store.save(value)
    def forget(self):self.store.delete()

def self_test(path):
    value={'server':CLOUD_ORIGIN,'token':secrets.token_urlsafe(40),'allowed_targets':['127.0.0.1','::1'],'allow_posture':True,'allow_updates':False}
    with disposable_keychain() as (security,keychain):
        store=KeychainStore(security,service=SERVICE+'.test-'+uuid.uuid4().hex,keychain=keychain)
        store.save(value)
        if store.load()!=value:raise ValueError('Keychain roundtrip did not match.')
        store.delete()
        if store.load() is not None:raise ValueError('Keychain test item was not removed.')
    from companion.device_agent import transport_context
    context=transport_context()
    if context.verify_mode!=ssl.CERT_REQUIRED or not context.check_hostname:raise ValueError('TLS verification was not configured.')
    with Path(path).open('x',encoding='utf-8') as handle:json.dump({'version':VERSION,'keychain_roundtrip':True,'storage_scope':'disposable-keychain-native-api','keychain_test_item_removed':True,'device_operator_imported':True,'tls_certificate_verification':True},handle)

def main():
    if len(sys.argv)==3 and sys.argv[1]=='--self-test':self_test(sys.argv[2]);return
    if platform.system()!='Darwin':raise ValueError('This app requires macOS.')
    from companion.helper_desktop import HelperApp
    HelperApp(MacAdapter()).run()

if __name__=='__main__':main()
