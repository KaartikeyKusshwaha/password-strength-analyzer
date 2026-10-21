import React,{useEffect,useState} from 'react';
import CloudConnect from './CloudConnect';
import SiteCheck from './SiteCheck';
import FileChecks from './FileChecks';
import DevicePairing from './DevicePairing';
import {securityRequest} from './security-client';

const PORTS=[21,22,23,25,53,80,110,143,443,3306,3389,5000,8000,8080,8443];
export default function SecurityAssistant({browser=chrome}){
  const [connection,setConnection]=useState(null),[context,setContext]=useState(null),[action,setAction]=useState('website'),[device,setDevice]=useState(''),[deviceTarget,setDeviceTarget]=useState('127.0.0.1'),[target,setTarget]=useState(''),[ai,setAi]=useState(false),[result,setResult]=useState(null),[running,setRunning]=useState(false),[error,setError]=useState('');
  async function load(value){setConnection(value);try{const context=await securityRequest(value,'/context');setContext(context);setAi(context.ai_available);setDevice(context.devices[0]?.id||'');setAction(context.devices.length?'device':'website');setTarget(context.scan_hosts[0]||'');}catch(e){setError(e.message);}}
  useEffect(()=>{let live=true;browser.storage.local.get(['securityConnection','securityOperation']).then(async saved=>{if(!live||!saved.securityConnection)return;await load(saved.securityConnection);if(live&&saved.securityOperation?.origin===saved.securityConnection.origin){setResult({id:saved.securityOperation.id,status:'queued'});setRunning(true);}});return()=>{live=false;};},[]);
  useEffect(()=>{if(!running||!result?.id||!connection)return;let live=true,inFlight=false;
    const check=async()=>{if(inFlight)return;inFlight=true;try{const value=await securityRequest(connection,'/operations/'+result.id);if(!live)return;setResult(value);if(!['queued','running'].includes(value.status)&&!['queued','running'].includes(value.ai_status)){setRunning(false);await browser.storage.local.remove('securityOperation');}}catch(e){if(live){setError(e.message);setRunning(false);}}finally{inFlight=false;}};
    check();const timer=setInterval(check,2500);return()=>{live=false;clearInterval(timer);};
  },[running,result?.id,connection]);
  const selected=context?.devices.find(item=>item.id===device);
  const approvedTarget=action==='website'?target:action==='device'?(selected?.targets.includes(deviceTarget)?deviceTarget:selected?.targets[0]):selected?.targets.find(value=>['127.0.0.1','::1'].includes(value));
  async function queued(value){await browser.storage.local.set({securityOperation:{id:value.id,origin:connection.origin}});setResult(value);setRunning(true);}
  async function run(){setError('');try{
    const body={action,authorized:true,ai_triage:ai,target:approvedTarget,device_id:action==='website'?'local':device,ports:PORTS};
    const value=await securityRequest(connection,'/operations',body);
    await queued(value);
  }catch(e){setError(e.message);}}
  return <><SiteCheck browser={browser}/><section aria-label="Security assistant"><h2>Your security assistant</h2>
    {!connection?<CloudConnect scope="security" browser={browser} onConnected={load}/>:!context?<><p>Checking security access…</p>{error&&<button className="secondary" onClick={async()=>{await browser.storage.local.remove('securityConnection');setConnection(null);setError('');}}>Forget local connection and reconnect</button>}</>:<>
      <p className="fine">Workspace: {context.workspace} · No vault contents are shared with AI.</p>
      <label>Check<select disabled={running} value={action} onChange={event=>setAction(event.target.value)}><option value="website">Approved website · runs in cloud</option><option value="device">Device ports · needs device helper</option><option value="posture">Windows protection · needs device helper</option><option value="updates">Cached Windows updates · needs device helper</option></select></label>
      {action==='website'?<label>Approved website<select disabled={running} value={target} onChange={event=>setTarget(event.target.value)}>{!context.scan_hosts.length&&<option value="">No approved websites</option>}{context.scan_hosts.map(host=><option key={host}>{host}</option>)}</select></label>:<><label>Device<select disabled={running} value={device} onChange={event=>setDevice(event.target.value)}>{!context.devices.length&&<option value="">Connect the optional device helper first</option>}{context.devices.map(item=><option key={item.id} value={item.id}>{item.label}</option>)}</select></label>{!selected&&<p>Needs device helper. The hosting server is never scanned in place of your computer.</p>}</>}
      <label><input type="checkbox" disabled={running||!context.ai_available} checked={ai} onChange={event=>setAi(event.target.checked)}/>Use AI to prioritize observations and create follow-up tasks</label>
      {action==='device'&&selected&&<label>Approved device IP<select disabled={running} value={approvedTarget||''} onChange={event=>setDeviceTarget(event.target.value)}>{selected.targets.map(value=><option key={value}>{value}</option>)}</select></label>}
      <p className="fine">Target: {approvedTarget||'No eligible target selected'}</p>
      <p className="fine">{action==='website'?'One HTTPS header check on the selected approved host.':action==='device'?'Check 15 TCP ports on the selected approved device IP through its helper.':action==='posture'?'Read firewall, Defender and system-drive encryption status on the selected Windows helper.':'Read the selected Windows helper’s offline update cache and restart status.'} No software changes or automatic repairs.</p>
      <button disabled={running||!approvedTarget||(action==='website'?!target:!selected)||action==='posture'&&!selected?.allow_posture||action==='updates'&&!selected?.allow_updates} onClick={run}>{running?'Checking your security…':'Approve and check my security'}</button>
      <FileChecks connection={connection} running={running} ai={ai} onQueued={queued}/>
      <DevicePairing connection={connection} enabled={context.device_pairing} helper={context.helper} running={running} browser={browser} onConnected={()=>load(connection)}/>
      {running&&<button className="secondary" onClick={async()=>{try{await securityRequest(connection,'/operations/'+result.id+'/cancel',{});setRunning(false);setResult({...result,status:'cancelled'});await browser.storage.local.remove('securityOperation');}catch(e){setError(e.message);}}}>Cancel check</button>}
      {result?.ai_error&&<p className="error" role="alert">{result.ai_error}</p>}
      {result?.observations?.length>0&&<details><summary>{result.finding_count} observations recorded</summary>{result.observations.map((item,index)=><article key={index}><strong>{item.title} · {item.severity}</strong><p>{item.line>0&&`Line ${item.line}. `}{item.package&&`${item.package.ecosystem} ${item.package.name}@${item.package.version} ${item.advisory||''}. `}{item.guidance}</p><a href={item.reference} target="_blank" rel="noreferrer">Review guidance</a></article>)}</details>}
      {result&&<><p role="status">{result.status==='cancelled'?'Check cancelled.':result.status==='complete'?(result.ai_status==='running'||result.ai_status==='queued'?'Preparing your action plan…':'Check finished.'):result.status==='partial'?'Some checks could not be completed.':result.status==='failed'?'Check failed; no complete assessment was produced.':'Collecting observations…'}</p>{result.summary&&<p>{result.summary}</p>}{result.error&&<p className="error">{result.error}</p>}{result.actions?.map((item,index)=><article key={index}><strong>{item.title}</strong><ul>{item.steps.slice(0,3).map((step,i)=><li key={i}>{step}</li>)}</ul><small>Verify: {item.verification}</small></article>)}<details><summary>Advanced · check details</summary><p>{result.action} · {result.target} · {result.status}</p><p>AI: {result.ai_status||'Not requested or no findings to plan'}</p><p>{result.coverage}</p>{result.dependency_coverage&&<p>{result.dependency_coverage.selected} selected packages; {result.dependency_coverage.excluded} excluded; {result.dependency_coverage.skipped_records} unsupported records skipped.</p>}<p>Actions are drafts, not completed repairs.</p></details></>}
      <button className="secondary" disabled={running} onClick={async()=>{try{await securityRequest(connection,'/revoke',{});await browser.storage.local.remove('securityConnection');setConnection(null);setContext(null);setResult(null);}catch(e){setError(e.message);}}}>Disconnect security agents</button>
    </>}{error&&<p role="alert" className="error">{error}</p>}</section></>;
}
