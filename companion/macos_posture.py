"""Three bounded, read-only macOS status commands; never security configuration."""
import os
import platform
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone

TOOLS={
 'application_firewall':('/usr/libexec/ApplicationFirewall/socketfilterfw','--getglobalstate'),
 'filevault':('/usr/bin/fdesetup','status'),
 'gatekeeper':('/usr/sbin/spctl','--status'),
}

def command(tool):
    if tool not in TOOLS:raise ValueError('Unsupported macOS posture tool.')
    if platform.system()!='Darwin':return {'error':'unsupported_platform'}
    try:
        result=subprocess.run(list(TOOLS[tool]),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,timeout=12,env={**os.environ,'LC_ALL':'C','LANG':'C'})
        if len(result.stdout)>4096 or len(result.stderr)>4096:return {'error':'invalid_response'}
        text=result.stdout.decode('utf-8',errors='strict').strip()
        # Only exact, known output is accepted; privilege/localization/provider
        # failures do not become an enabled or clean status.
        if result.returncode not in {0,1}:return {'error':'provider_error'}
        if tool=='application_firewall':
            match=re.fullmatch(r'Firewall is (enabled|disabled)\. \(State = ([012])\)',text)
            if match and (match[1]=='disabled')==(match[2]=='0') and (result.returncode==0 or match[2]=='0'):return {'state':'disabled' if match[2]=='0' else 'enabled'}
        elif tool=='filevault' and text in {'FileVault is On.','FileVault is Off.'} and (result.returncode==0 or text=='FileVault is Off.'):return {'state':'enabled' if text=='FileVault is On.' else 'disabled'}
        elif tool=='gatekeeper' and text in {'assessments enabled','assessments disabled'} and (result.returncode==0 or text.endswith('disabled')):return {'state':'enabled' if text.endswith('enabled') else 'disabled'}
        return {'error':'unknown_status'}
    except subprocess.TimeoutExpired:return {'error':'timeout'}
    except PermissionError:return {'error':'permission_denied'}
    except FileNotFoundError:return {'error':'command_unavailable'}
    except (OSError,UnicodeError):return {'error':'invalid_response'}

def collect(runner=command):
    with ThreadPoolExecutor(max_workers=3) as pool:values=dict(zip(TOOLS,pool.map(runner,TOOLS)))
    checks=[]
    for tool,value in values.items():
        if isinstance(value,dict) and value.get('state') in {'enabled','disabled'}:checks.append({'id':tool,'state':value['state'],'reason':''})
        else:
            reason=value.get('error') if isinstance(value,dict) else None
            checks.append({'id':tool,'state':'unassessed','reason':reason if reason in {'timeout','permission_denied','command_unavailable','provider_error','invalid_response','unknown_status'} else 'invalid_response'})
    return {'version':2,'platform':'macos','generated_at':datetime.now(timezone.utc).isoformat(),'checks':checks}
