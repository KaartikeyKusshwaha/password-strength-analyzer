"""Desktop pairing client: proof stays on device, tokens use current-user DPAPI."""
import ctypes
import json
import os
import re
import secrets
import time
import urllib.request
from pathlib import Path
from companion.device_agent import secure_opener,validate_connection

CLOUD_ORIGIN='https://sentinelops-pilot.onrender.com'
VERSION='0.2.0'

def protect(value,decrypt=False):
    if os.name!='nt':raise ValueError('Protected device storage requires Windows.')
    from ctypes import wintypes
    class Blob(ctypes.Structure):
        _fields_=[('size',wintypes.DWORD),('data',ctypes.POINTER(ctypes.c_ubyte))]
    buffer=ctypes.create_string_buffer(value)
    source=Blob(len(value),ctypes.cast(buffer,ctypes.POINTER(ctypes.c_ubyte)));result=Blob()
    crypt=ctypes.WinDLL('crypt32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.LocalFree.argtypes=[ctypes.c_void_p];kernel.LocalFree.restype=ctypes.c_void_p
    function=crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    function.argtypes=[ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(Blob)];function.restype=wintypes.BOOL
    if not function(ctypes.byref(source),None,None,None,None,1,ctypes.byref(result)):
        raise ValueError('Windows could not protect or unlock the device connection.')
    try:return ctypes.string_at(result.data,result.size)
    finally:kernel.LocalFree(result.data)

def data_directory():
    base=Path(os.environ.get('LOCALAPPDATA',''))
    if not base.is_absolute():raise ValueError('Windows user application-data folder unavailable.')
    target=base/'SentinelOpsDeviceHelper'
    if target.is_symlink() or target.is_junction():raise ValueError('Linked helper folders are unsupported.')
    return target

def save_connection(path,value,protector=protect):
    validate_connection(value)
    if value['server']!=CLOUD_ORIGIN or value['allowed_targets']!=['127.0.0.1','::1']:raise ValueError('Unexpected helper scope.')
    encrypted=protector(json.dumps(value,separators=(',',':')).encode())
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    if path.is_symlink():raise ValueError('Linked connection files are unsupported.')
    temporary=path.with_suffix('.new')
    if temporary.exists():raise ValueError('A connection update is already pending.')
    try:
        with temporary.open('xb') as handle:handle.write(encrypted)
        temporary.replace(path)
    finally:temporary.unlink(missing_ok=True)

def load_connection(path,protector=protect):
    path=Path(path)
    if path.is_symlink() or path.stat().st_size>20000:raise ValueError('Invalid protected connection file.')
    value=validate_connection(json.loads(protector(path.read_bytes(),decrypt=True)))
    if value['server']!=CLOUD_ORIGIN or value['allowed_targets']!=['127.0.0.1','::1']:raise ValueError('Unexpected helper scope.')
    return value

def public_request(path,body):
    if not re.fullmatch(r'/api/device-pairing/(?:start|[a-f0-9]{24}/(?:poll|ack|cancel))',path):raise ValueError('Unsupported helper request.')
    request=urllib.request.Request(CLOUD_ORIGIN+path,data=json.dumps(body).encode(),method='POST',headers={'Content-Type':'application/json'})
    with secure_opener().open(request,timeout=12) as response:
        raw=response.read(100001)
        if len(raw)>100000:raise ValueError('Pairing response exceeded limit.')
        return json.loads(raw)

class Pairing:
    def __init__(self,label,allow_posture,allow_updates,requester=public_request):
        self.requester=requester;self.proof=secrets.token_urlsafe(32);self.options={'label':label,'allow_posture':bool(allow_posture),'allow_updates':bool(allow_updates)}
        self.pending=None
    def start(self):
        value=self.requester('/api/device-pairing/start',{'proof':self.proof,**self.options})
        if not re.fullmatch(r'[a-f0-9]{24}',value.get('id','')) or not re.fullmatch(r'[A-HJ-NP-Z2-9]{8}',value.get('pairing_code','')) or value.get('server')!=CLOUD_ORIGIN or not isinstance(value.get('expires'),(int,float)) or not time.time()<value['expires']<=time.time()+310:raise ValueError('Unexpected pairing response.')
        self.pending=value;return value
    def poll(self):
        if not self.pending or self.pending['expires']<=time.time():raise ValueError('Pairing expired. Start again.')
        result=self.requester('/api/device-pairing/'+self.pending['id']+'/poll',{'proof':self.proof})
        if result.get('status')=='pending':return None
        if result.get('status')!='approved':raise ValueError('Unexpected pairing state.')
        config=validate_connection(result['connection'])
        if config['server']!=CLOUD_ORIGIN or config['allowed_targets']!=['127.0.0.1','::1'] or any(config.get(key)!=self.options[key] for key in ('allow_posture','allow_updates')):raise ValueError('Helper scope changed. Nothing was connected.')
        return config
    def acknowledge(self):
        return self.requester('/api/device-pairing/'+self.pending['id']+'/ack',{'proof':self.proof})
    def cancel(self):
        if self.pending:return self.requester('/api/device-pairing/'+self.pending['id']+'/cancel',{'proof':self.proof})
