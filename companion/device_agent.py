#!/usr/bin/env python3
"""SentinelOps local companion. Standard library only. No installer or server.

Legacy report: python sentinelops_device_agent.py --consent --output device-report.json
Paired mode polls explicitly scoped private TCP jobs and uploads observations.
Optional --allow-posture also allows fixed read-only Windows status commands on
this computer when the connection opted in. No arbitrary commands, elevation,
system changes, process inventory, recovery keys or background telemetry.
Separate --allow-updates reads Windows Update offline-cache counts and update
reboot status only; it does not refresh online, install or restart.
"""
import argparse
import json
import socket
import ipaddress
import re
import time
import urllib.request
import urllib.parse
import urllib.error
import os
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

PORTS = (21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5000, 8000, 8080, 8443)
VERSION='0.8.0'
HOSTS = ("127.0.0.1", "::1")
POSTURE_CHECKS=('firewall_domain','firewall_private','firewall_public','defender','system_disk')
# Fixed read-only tools. No target, job text or user input is interpolated.
POSTURE_SCRIPTS={
    'firewall':"$v=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Select-Object Name,Enabled);$v | ConvertTo-Json -Compress",
    'defender':"Get-MpComputerStatus -ErrorAction Stop | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AMRunningMode | ConvertTo-Json -Compress",
    'system_disk':"$v=@(Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Property DriveLetter,DeviceID -ErrorAction Stop | Where-Object {$_.DriveLetter -eq $env:SystemDrive});if($v.Count -ne 1){'{\"error\":\"provider_error\"}'}else{$v[0] | Invoke-CimMethod -MethodName GetProtectionStatus -ErrorAction Stop | Select-Object ProtectionStatus,ReturnValue | ConvertTo-Json -Compress}",
}


def posture_command(tool):
    if tool not in POSTURE_SCRIPTS:
        raise ValueError('Unsupported posture tool.')
    return fixed_command(POSTURE_SCRIPTS[tool],15)


def fixed_command(source,timeout):
    executable=Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32/WindowsPowerShell/v1.0/powershell.exe'
    if not executable.is_absolute() or not executable.is_file():
        return {'error':'command_unavailable'}
    script="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);try{"+source+"}catch{if($_.CategoryInfo.Category -in @('PermissionDenied','SecurityError')){'{\"error\":\"permission_denied\"}'}elseif($_.Exception -is [System.Management.Automation.CommandNotFoundException]){'{\"error\":\"command_unavailable\"}'}else{'{\"error\":\"provider_error\"}'}}"
    try:
        result=subprocess.run([str(executable),'-NoLogo','-NoProfile','-NonInteractive','-Command',script],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,shell=False,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if result.returncode or len(result.stdout)>12000:
            return {'error':'provider_error'}
        return json.loads(result.stdout.decode('utf-8-sig'))
    except subprocess.TimeoutExpired:
        return {'error':'timeout'}
    except (OSError,ValueError,UnicodeError):
        return {'error':'invalid_response'}


UPDATE_SCRIPTS={
    'cache':"$session=New-Object -ComObject Microsoft.Update.Session;$searcher=$session.CreateUpdateSearcher();$searcher.Online=$false;$result=$searcher.Search(\"IsInstalled=0 and IsHidden=0 and Type='Software'\");if([int]$result.ResultCode -ne 2){'{\"error\":\"provider_error\"}'}else{$count=[int]$result.Updates.Count;if($count -gt 10000){'{\"error\":\"invalid_response\"}'}else{$security=0;foreach($update in $result.Updates){$matched=$false;foreach($category in $update.Categories){if($category.CategoryID -in @('0fa1201d-4330-4fa8-8ae9-b877473b6441','e6cf1350-c01b-414d-a61f-263d14d133b4')){$matched=$true}};if($matched){$security++}};@{pending=$count;security=$security} | ConvertTo-Json -Compress}}",
    'reboot':"$information=New-Object -ComObject Microsoft.Update.SystemInfo;@{required=[bool]$information.RebootRequired} | ConvertTo-Json -Compress",
}


def update_command(tool):
    if tool not in UPDATE_SCRIPTS:raise ValueError('Unsupported update tool.')
    return fixed_command(UPDATE_SCRIPTS[tool],35)


def collect_updates(runner=update_command,system=None):
    system=system or platform.system()
    report={'version':1,'platform':{'Windows':'windows','Linux':'linux','Darwin':'macos'}.get(system,'other'),'generated_at':datetime.now(timezone.utc).isoformat(),'source':'windows-update-offline-cache'}
    if system!='Windows':
        report.update(cache={'state':'unsupported','reason':'unsupported_platform'},reboot={'state':'unsupported','reason':'unsupported_platform'})
        return report
    def unknown(value):
        reason=value.get('error') if isinstance(value,dict) else None
        return {'state':'unassessed','reason':reason if reason in {'permission_denied','command_unavailable','timeout','provider_error','invalid_response','unknown_status'} else 'invalid_response'}
    with ThreadPoolExecutor(max_workers=2) as pool:
        values=dict(zip(UPDATE_SCRIPTS,pool.map(runner,UPDATE_SCRIPTS)))
    cache=values['cache']
    if isinstance(cache,dict) and type(cache.get('pending')) is int and type(cache.get('security')) is int and 0<=cache['security']<=cache['pending']<=10000:
        report['cache']={'state':'observed','reason':'','pending':cache['pending'],'security':cache['security']}
    else:report['cache']=unknown(cache)
    reboot=values['reboot']
    report['reboot']={'state':'observed','reason':'','required':reboot['required']} if isinstance(reboot,dict) and type(reboot.get('required')) is bool else unknown(reboot)
    return report


def collect_posture(runner=posture_command,system=None):
    system=system or platform.system()
    report={'version':1,'platform':{'Windows':'windows','Linux':'linux','Darwin':'macos'}.get(system,'other'),'generated_at':datetime.now(timezone.utc).isoformat(),'checks':[]}
    if system!='Windows':
        report['checks']=[{'id':check,'state':'unsupported','reason':'unsupported_platform'} for check in POSTURE_CHECKS]
        return report
    def unknown(check,value):
        reason=value.get('error') if isinstance(value,dict) else None
        return {'id':check,'state':'unassessed','reason':reason if reason in {'permission_denied','command_unavailable','timeout','provider_error','invalid_response','unknown_status'} else 'invalid_response'}
    with ThreadPoolExecutor(max_workers=3) as pool:
        values=dict(zip(POSTURE_SCRIPTS,pool.map(runner,POSTURE_SCRIPTS)))
    profiles=values['firewall'];profiles=[profiles] if isinstance(profiles,dict) and 'Name' in profiles else profiles
    for name in ('Domain','Private','Public'):
        matches=[item for item in profiles if isinstance(item,dict) and item.get('Name')==name] if isinstance(profiles,list) else []
        item=matches[0] if len(matches)==1 else None
        # CIM may serialize the Enabled enum as True/False or 1/0.
        value=item.get('Enabled') if item else None
        state='enabled' if value is True or type(value) is int and value==1 else 'disabled' if value is False or type(value) is int and value==0 else None
        report['checks'].append({'id':'firewall_'+name.lower(),'state':state,'reason':''} if state else unknown('firewall_'+name.lower(),values['firewall']))
    defender=values['defender']
    if isinstance(defender,dict) and type(defender.get('AntivirusEnabled')) is bool and type(defender.get('RealTimeProtectionEnabled')) is bool:
        mode=defender.get('AMRunningMode')
        if mode in {'Passive Mode','SxS Passive Mode','EDR Block Mode'}:
            state='passive'
        elif mode in {'Normal',None}:
            state='enabled' if defender['AntivirusEnabled'] and defender['RealTimeProtectionEnabled'] else 'disabled'
        else:
            state=None
        report['checks'].append({'id':'defender','state':state,'reason':''} if state else unknown('defender',defender))
    else:
        report['checks'].append(unknown('defender',defender))
    disk=values['system_disk'];protection=disk.get('ProtectionStatus') if isinstance(disk,dict) and type(disk.get('ReturnValue')) is int and disk['ReturnValue']==0 else None
    state='enabled' if protection=='On' or type(protection) is int and protection==1 else 'disabled' if protection=='Off' or type(protection) is int and protection==0 else None
    report['checks'].append({'id':'system_disk','state':state,'reason':''} if state else unknown('system_disk',{'error':'unknown_status'} if protection==2 else disk))
    return report


def check(pair):
    host, port = pair
    try:
        with socket.create_connection((host, port), timeout=0.35):
            status = "open"
    except ConnectionRefusedError:
        status = "closed"
    except OSError:
        status = "unassessed"
    return {"host": host, "port": port, "status": status}


def assess():
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(check, [(host, port) for host in HOSTS for port in PORTS]))
    return {"version": 1, "generated_at": datetime.now(timezone.utc).isoformat(), "scope": "fixed-loopback-tcp", "observations": results}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward a device bearer token through a redirect.


def connection_file(path):
    if Path(path).stat().st_size > 12000:
        raise ValueError("Connection file is too large.")
    value = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    url = urllib.parse.urlsplit(value['server'])
    if not (url.scheme == 'https' or url.scheme == 'http' and url.hostname in {'localhost','127.0.0.1'}) or not url.hostname or url.username or url.password or url.path not in {'','/'} or url.query or url.fragment:
        raise ValueError("Connection server must be an HTTPS origin or local loopback origin.")
    if not re.fullmatch(r'[A-Za-z0-9_-]{40,100}', value.get('token','')):
        raise ValueError("Invalid device token.")
    targets = value.get('allowed_targets', [])
    if 'allow_updates' in value and type(value['allow_updates']) is not bool:
        raise ValueError('Invalid update-status permission.')
    if 'allow_posture' in value and type(value['allow_posture']) is not bool:
        raise ValueError('Invalid posture permission.')
    if not 1 <= len(targets) <= 16:
        raise ValueError("Connection must explicitly allow 1–16 individual private targets.")
    for target in targets:
        address = ipaddress.ip_address(target)
        private_lan = address.version == 4 and any(address in ipaddress.ip_network(net) for net in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')) or address.version == 6 and address in ipaddress.ip_network('fc00::/7')
        if not (address.is_loopback or private_lan) or address.is_link_local or address.is_multicast or address.is_unspecified or address.version == 4 and str(address).endswith('.255'):
            raise ValueError("Public, metadata and link-local targets are not allowed.")
    value['server'] = value['server'].rstrip('/')
    return value


def api_request(config, path, body):
    request = urllib.request.Request(config['server'] + path, data=json.dumps(body).encode(), method='POST', headers={'Authorization':'Bearer '+config['token'], 'Content-Type':'application/json'})
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=12) as response:
        raw = response.read(100001)
        if len(raw) > 100000:
            raise ValueError("Device server response exceeded limit.")
        return json.loads(raw)


def poll_once(config, requester=api_request,allow_posture=False,allow_updates=False):
    job = requester(config, '/api/device-agent/poll', {'version':3,'posture_enabled':bool(allow_posture and config.get('allow_posture')),'updates_enabled':bool(allow_updates and config.get('allow_updates'))}).get('operation')
    if not job:
        return False
    action=job.get('action','device')
    if action not in {'device','posture','updates'}:
        raise ValueError('This client does not support the requested tool.')
    if action=='posture':
        if not allow_posture or not config.get('allow_posture') or job.get('target') not in {'127.0.0.1','::1'} or job.get('target') not in config['allowed_targets'] or job.get('ports')!=[]:
            raise ValueError('Host posture collection requires explicit local and connection consent; nothing was collected.')
    if action=='updates' and (not allow_updates or not config.get('allow_updates') or job.get('target') not in {'127.0.0.1','::1'} or job.get('target') not in config['allowed_targets'] or job.get('ports')!=[]):
        raise ValueError('Update status requires separate local and connection consent; nothing was collected.')
    target, ports = job.get('target'), job.get('ports')
    if action=='device' and (target not in config['allowed_targets'] or not isinstance(ports,list) or not 1 <= len(ports) <= 64 or len(set(ports)) != len(ports) or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)):
        raise ValueError("Job is outside this device's authorized scope; nothing was assessed.")
    if not isinstance(job.get('id'),str) or len(job['id']) > 60 or not re.fullmatch(r'[A-Za-z0-9_-]{30,100}', job.get('lease','')):
        raise ValueError("Invalid job lease.")
    if action=='updates':
        result={'observations':[],'updates':collect_updates()}
    elif action=='posture':
        result={'observations':[],'posture':collect_posture()}
    else:
        with ThreadPoolExecutor(max_workers=8) as pool:
            result={'observations':list(pool.map(check,[(target,port) for port in ports]))}
    requester(config, '/api/device-agent/result', {'operation_id':job['id'], 'lease':job['lease'], **result})
    return True


def serve(path, once=False,allow_posture=False,allow_updates=False):
    config = connection_file(path)
    print('Device connected. Only approved private TCP targets and separately opted-in fixed host protection / offline update-status tools are supported. No arbitrary commands, elevation or system changes. Stop with Ctrl+C.')
    while True:
        try:
            completed = poll_once(config,allow_posture=allow_posture,allow_updates=allow_updates)
            if completed:
                print('Assessment results synchronized with your dashboard.')
        except urllib.error.HTTPError as error:
            if error.code == 401:
                raise ValueError('Device connection expired or revoked. Create a new connection in your dashboard.')
            print('Device server rejected this request; no substitute results were generated.')
            if once:
                raise
        except (OSError, ValueError):
            if once:
                raise
            print('Device connection unavailable or job rejected. Check the server and authorized scope. No results were invented.')
        if once:
            return
        time.sleep(5)


def main():
    parser = argparse.ArgumentParser(description="Inspect fixed TCP ports on this computer's loopback interfaces.")
    parser.add_argument('--version',action='version',version='SentinelOps device agent '+VERSION)
    parser.add_argument("--consent", action="store_true", help="Confirm you may inspect this computer")
    parser.add_argument("--output", default="device-report.json")
    parser.add_argument("--connect", help="Private connection JSON downloaded from SentinelOps; polls authorized jobs and uploads results")
    parser.add_argument("--once", action="store_true", help="Poll at most one job, then exit")
    parser.add_argument('--allow-posture',action='store_true',help='Allow fixed read-only Windows firewall, Defender and system-drive BitLocker status commands for this agent computer')
    parser.add_argument('--allow-updates',action='store_true',help='Allow read-only Windows Update offline cache and update reboot status; no online refresh or installation')
    args = parser.parse_args()
    if not args.consent:
        parser.error("Read the scope above, then add --consent if you are authorized.")
    if args.connect:
        try:
            serve(args.connect,args.once,args.allow_posture,args.allow_updates)
        except KeyboardInterrupt:
            print('Device disconnected.')
        except (ValueError, OSError, KeyError):
            parser.error('Could not connect. Check the private connection file, token expiry and server. No credentials were printed.')
        return
    target = Path(args.output)
    if target.exists():
        parser.error("Output already exists. Choose another filename; existing reports are never overwritten.")
    result = assess()
    with target.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    counts = {status: sum(p["status"] == status for p in result["observations"]) for status in ("open", "closed", "unassessed")}
    print(f"Report saved to {target.name}: {counts}. No data was uploaded.")


if __name__ == "__main__":
    main()
