import { useState } from 'react';
import { Bot, Monitor, Globe, KeyRound, FileSearch, ArrowRight, ShieldCheck, LoaderCircle } from 'lucide-react';
import { api } from './api';
import {ActionFeed} from './AccountActions';
import DevicePosture from './DevicePosture';

const options = [
  ['device', Monitor, 'Check a device', 'Inspect selected TCP ports and record the results.'],
  ['website', Globe, 'Check a website', 'Assess an authorized website’s HTTPS response.'],
  ['accounts', KeyRound, 'Protect my accounts', 'Review saved logins, change passwords and manage 2FA.'],
  ['python', FileSearch, 'Review code or a message', 'Check Python, dependency pins or suspicious email.'],
];
export default function ControlCenter({ data, refresh, go, canWrite }) {
  const [deviceMode,setDeviceMode]=useState('device');
  const [action, setAction] = useState('device'), [busy, setBusy] = useState(false),
    [error, setError] = useState(''), [notice, setNotice] = useState('');
  const operations = data.operations || [];
  const devices = data.devices || [];
  const deviceAvailable = data.integrations.local_device_agent || devices.length > 0;
  const postureAvailable=data.integrations.local_device_agent || devices.some(device=>device.allow_posture);
  const active = operations.some(o => ['queued', 'running'].includes(o.status));
  return <>
    {!!data.ownership_requests?.length && <section className="panel spaced"><span className="eyebrow">OWNERSHIP REQUESTS</span><h2>A shared vault needs your decision.</h2>{data.ownership_requests.map(request=><p key={request.id}><strong>{request.vault_name}</strong> · proposal expires {new Date(request.expires_at*1000).toLocaleString()}</p>)}<button className="button" onClick={()=>go('shared-vaults')}>Review shared vault ownership</button><p className="fine">Open your sharing identity and verify the current owner before accepting. Ownership has not changed yet.</p></section>}
    <div className="connection-strip"><button onClick={() => go('vault')}><KeyRound size={16}/>{data.connections?.vault_created ? 'Personal vault created' : 'Create your private vault'}</button><button onClick={() => go('companions')}><Globe size={16}/>{data.connections?.browser_tokens ? `${data.connections.browser_tokens} browser token(s) issued` : 'Connect your browser'}</button><span><Monitor size={16}/>{data.integrations.local_device_agent ? 'Local device operator available' : 'Device connection needed'}</span></div>
    <section className="panel control-center">
      <div className="control-intro"><span className="eyebrow">YOUR SECURITY CONTROL CENTER</span><h2>What should we take care of?</h2><p>Choose an outcome. Your operators collect evidence, record findings and carry approved work forward.</p></div>
      <div className="operator-options">{options.map(([id, Icon, title, description]) => <button key={id} className={action === id ? 'operator-option selected' : 'operator-option'} onClick={() => { setAction(id); setError(''); setNotice(''); }}><Icon size={22} /><strong>{title}</strong><span>{description}</span></button>)}</div>
      {error && <p role="alert" className="notice error">{error}</p>}
      {notice && <p role="status" className="notice">{notice}</p>}
      {action === 'accounts' ? <div className="operator-account"><KeyRound size={28}/><div><h3>Your vaults, connected to your browser</h3><p>Create or unlock your vault, review weak or reused passwords, and approve a private queue of account security actions. The browser assistant handles password suggestions and saving on supported forms. Your encrypted vault syncs through this backend.</p></div><button className="button" onClick={() => go('vault')}>Open my accounts <ArrowRight size={16}/></button><button className="button secondary" onClick={() => go('companions')}>Connect browser</button></div> : <form className="operator-form" onSubmit={async event => {
        event.preventDefault(); setBusy(true); setError(''); setNotice('');
        const form = event.currentTarget, values = new FormData(form);
        try {
          const kind = values.get('kind') || action;
          const ports = (values.get('ports') || '21,22,23,25,53,80,110,143,443,3306,3389,5000,8000,8080,8443').split(',').map(p => Number(p.trim()));
          if (kind === 'device' && (!ports.length || ports.length > 64 || ports.some(p => !Number.isInteger(p) || p < 1 || p > 65535))) throw new Error('Enter up to 64 comma-separated TCP ports from 1 to 65535.');
          let content = values.get('content') || '';
          const file = form.elements.file?.files[0];
          if (file?.size > 100000) throw new Error('Choose a file under 100 KB.');
          if (file) content = await file.text();
          await api('/operations', {action: kind, target: kind==='posture'?'127.0.0.1':values.get('target') || '127.0.0.1', ports, content, format: values.get('format') || 'requirements', authorized: values.has('authorized'), ai_triage: values.has('ai_triage'), device_id: ['device','posture'].includes(kind) ? values.get('device_id') || 'local' : 'local'});
          await refresh(); setNotice('Operator started. Results and any approved remediation tasks will appear below.');
        } catch (e) { setError(e.message); } finally { setBusy(false); }
      }}>
        {action === 'device' && <><label>Device assessment<select name="kind" value={deviceMode} onChange={event=>setDeviceMode(event.target.value)}><option value="device">Selected TCP ports</option><option value="posture">Host protection status · Windows</option></select></label><label>Run on this device connection<select key={deviceMode} name="device_id">{data.integrations.local_device_agent && <option value="local">This local SentinelOps installation</option>}{devices.filter(device=>deviceMode!=='posture' || device.allow_posture).map(device => <option key={device.id} value={device.id}>{device.label} · {device.seen && Date.now()/1000-device.seen < 20 ? 'connected' : 'waiting for device'}</option>)}</select></label>{deviceMode==='device' && <><label>Device IP address<input name="target" defaultValue="127.0.0.1" placeholder="192.168.1.10" required/></label><label>TCP ports<input name="ports" defaultValue="21,22,23,25,53,80,110,143,443,3306,3389,5000,8000,8080,8443" required/></label></>}<p className="fine">127.0.0.1 is the computer running the selected operator. Enter one private LAN IP within that connection’s allowed scope for another authorized device. Open ports are observations; they do not prove vulnerabilities.</p>{deviceMode==='posture' && <p className="notice">Read-only firewall, Defender and system-drive BitLocker status on the selected agent computer. No LAN-device OS inspection or settings changes. Remote connections must opt in and run agent 0.7+ with --allow-posture; unavailable modules/permissions remain unassessed. Non-Windows checks are unsupported.</p>}{deviceMode==='posture' && !postureAvailable && <p className="notice">No device connection has granted host posture access. Create an opted-in device connection in Browser & devices first.</p>}{!deviceAvailable && <p className="notice">This hosted installation needs a device connection before it can inspect your network. It will not scan the hosting server in place of your device.</p>}</>}
        {action === 'website' && <><label>Website hostname<input name="target" placeholder="app.yourcompany.com" required/></label><p className="fine">Use an exact hostname from your operator’s configured assessment scope. One HTTPS response is assessed.</p></>}
        {action === 'python' && <><label>Check type<select name="kind"><option value="python">Python security patterns</option><option value="dependencies">Exact dependency vulnerabilities</option><option value="email">Suspicious email indicators</option></select></label><label>Content<textarea name="content" rows={5} placeholder="Paste code, pinned dependencies or a suspicious message"/></label><label>Or attach a text file<input name="file" type="file" accept=".py,.txt,.json,.eml"/></label><label>Dependency format<select name="format"><option value="requirements">requirements.txt</option><option value="package-json">package.json</option></select></label><p className="fine">Content is processed in memory and excluded from AI input and stored run history.</p></>}
        <label className="check"><input name="authorized" type="checkbox" required/>I own this target or have permission to assess it.</label>
        <label className="check"><input name="ai_triage" type="checkbox" disabled={!data.integrations.groq_configured}/>After assessment, use AI to plan remediation and create tasks assigned to me.</label>
        {!data.integrations.groq_configured && <p className="fine">Checks work without an AI key. Connect Groq to enable the optional AI planning step.</p>}
        <button className="button" disabled={busy || active || !canWrite || (action === 'device' && !(deviceMode==='posture'?postureAvailable:deviceAvailable))}>{busy || active ? <LoaderCircle size={16} className="spin"/> : <Bot size={16}/>} {busy ? 'Starting…' : active ? 'Operator is working…' : 'Run security operator'}</button>
      </form>}
    </section>
    <section className="panel operation-feed"><div className="panel-heading"><div><span className="eyebrow">REAL EXECUTION, RECORDED RESULTS</span><h2>Operations</h2></div><ShieldCheck size={22}/></div>{operations.length ? operations.slice(0, 8).map(o => <article key={o.id} className="operation-record"><div className="panel-heading"><strong>{o.action} · {o.target}</strong><span className={'badge '+o.status}>{o.status}</span></div><p className="fine">{new Date(o.created_at).toLocaleString()}</p>{o.steps.map((s, i) => <p key={i} className="fine">{s.agent} · {s.status}</p>)}{o.error && <p className="notice error">{o.error}</p>}{o.scan_id && <><p>{o.finding_ids.length} observations recorded.</p><button className="text-button" onClick={() => go('findings')}>Review findings →</button></>}{o.agent_job && <button className="text-button" onClick={() => go('agents')}>Follow remediation workflow →</button>}{['queued','running'].includes(o.status) && canWrite && <button className="text-button" onClick={async()=>{try{await api('/operations/'+o.id+'/cancel',{});await refresh();}catch(error){setError(error.message);}}}>Cancel operation</button>}<DevicePosture report={data.scans?.find(scan=>scan.id===o.scan_id)?.posture}/>{o.limits && <p className="fine">{o.limits}</p>}</article>) : <p className="muted">Your first operation will appear here after you run it. No sample results are added.</p>}</section>
    {action==='accounts' && <section className="panel spaced"><ActionFeed go={go}/></section>}
  </>;
}
