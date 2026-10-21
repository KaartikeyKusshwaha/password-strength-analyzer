import {useState} from 'react';
import {api} from './api';

export default function SecuritySweep({data,me,canWrite,refresh,go,chooseCheck}) {
  const devices=data.devices||[],local=data.integrations.local_device_agent;
  const [device,setDevice]=useState(local?'local':devices[0]?.id||''),[busy,setBusy]=useState(false),[error,setError]=useState('');
  const selected=devices.find(d=>d.id===device),tools=['device',...(device==='local'||selected?.allow_posture?['posture']:[]),...(device==='local'||selected?.allow_updates?['updates']:[])];
  const active=[...(data.operations||[]),...(data.jobs||[]),...(data.security_reviews||[])].some(v=>['queued','running'].includes(v.status));
  return <section id="automatic-device-check" className="panel spaced"><span className="eyebrow">AUTOMATIC SECURITY AGENTS</span><h2>Check my device and organize the work.</h2><p>One approval starts the available device checks. Agents record findings, prepare an AI plan and link or create follow-up tasks.</p>
    {chooseCheck&&<div className="inline" role="group" aria-label="Other vulnerability operators"><button className="button secondary" onClick={()=>chooseCheck('website')}>Check my website</button><button className="button secondary" onClick={()=>chooseCheck('dependencies')}>Check my dependencies</button></div>}
    {error&&<p role="alert" className="notice error">{error}</p>}
    <form className="operator-form" onSubmit={async event=>{
      event.preventDefault();setBusy(true);setError('');
      const fields=new FormData(event.currentTarget);
      try {
        const checks=tools.map(action=>({action,target:'127.0.0.1',device_id:device,authorized:true,...(action==='device'?{ports:[21,22,23,25,53,80,110,143,443,3306,3389,5000,8000,8080,8110,8443]}:{})}));
        await api('/security-reviews',{workspace_id:me.workspace,name:'Automatic device security check',checks,authorized:fields.has('authorized'),ai_triage:fields.has('ai_triage')});
        await refresh();go('reviews');
      }catch(error){setError(error.message);}finally{setBusy(false);}
    }}>
      <label>Device for automatic check<select value={device} onChange={e=>setDevice(e.target.value)} required><option value="" disabled>Connect a device first</option>{local&&<option value="local">This local SentinelOps computer</option>}{devices.map(d=><option key={d.id} value={d.id}>{d.label}</option>)}</select></label>
      <p className="fine">Scope: selected agent computer, 16 common TCP ports{tools.includes('posture')?', Windows firewall/Defender/system-drive protection':''}{tools.includes('updates')?', cached Windows Update/restart status':''}. Only separately granted tools are included. No software installation, settings changes or account password changes.</p>
      <label className="check"><input type="checkbox" name="ai_triage" defaultChecked={!!data.integrations.groq_configured} disabled={!data.integrations.groq_configured}/>Automatically prioritize findings with AI and link or create tasks assigned to me.</label>
      <label className="check"><input type="checkbox" name="authorized" required/>I authorize these checks on my selected device.</label>
      <button className="button" disabled={busy||active||!canWrite||!device}>{busy?'Starting agents…':'Approve and run agents'}</button>
    </form>
  </section>;
}
