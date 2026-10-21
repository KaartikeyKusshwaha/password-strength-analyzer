import {useState} from 'react';
import {api} from './api';
import DevicePosture from './DevicePosture';
import DeviceUpdates from './DeviceUpdates';
import PortCoverage from './PortCoverage';
import AdvisoryCoverage from './AdvisoryCoverage';
import MailCoverage from './MailCoverage';
import DependencyScope,{emptyDependency,dependencyReady,DependencyCoverage} from './DependencyScope';

const labels={device:'Device ports',posture:'Windows protection status',updates:'Windows Update cache & restart',website:'Website headers',python:'Python security patterns',dependencies:'Dependency advisories'};
const active=value=>['queued','running'].includes(value.status);

function ReviewStep({step,scans=[]}) {
  const scan=scans.find(value=>value.id===step.scan_id);
  return <li>{labels[step.action]} · {step.target} · {step.status}
    {step.error&&<p className="fine">{step.error}</p>}
    {scan?.error&&scan.error!==step.error&&<p className="fine">{scan.error}</p>}
    <DependencyCoverage coverage={scan?.dependency_inventory}/><MailCoverage coverage={scan?.mail_coverage}/><DeviceUpdates report={scan?.updates}/><DevicePosture report={scan?.posture}/><PortCoverage observations={scan?.observations}/><AdvisoryCoverage coverage={scan?.advisory_details}/>
  </li>;
}

export default function SecurityReviews({data,me,refresh,go,canWrite}) {
  const [dependency,setDependency]=useState(emptyDependency);
  const [checks,setChecks]=useState([]),[action,setAction]=useState('python'),[target,setTarget]=useState('127.0.0.1'),[content,setContent]=useState(''),[ports,setPorts]=useState('22,443'),[device,setDevice]=useState('local');
  const [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
  const reviews=data.security_reviews||[],reserved=reviews.some(active)||(data.operations||[]).some(active)||(data.jobs||[]).some(active);
  const isDevice=['device','posture','updates'].includes(action),isContent=['python','dependencies'].includes(action);
  const local=data.integrations.local_device_agent,devices=(data.devices||[]).filter(d=>action==='posture'?d.allow_posture:action==='updates'?d.allow_updates:true);
  function add(event) {
    event.preventDefault();setError('');setNotice('');
    try {
      if(checks.length>=6)throw new Error('Use up to six checks per review.');
      if(isDevice && device==='local'&&!local)throw new Error('Select a connected device first.');
      const check={action,authorized:true};
      if(isDevice){check.device_id=device;check.target=['posture','updates'].includes(action)?'127.0.0.1':target;}
      if(action==='device') {
        if(!/^\s*\d+(?:\s*,\s*\d+)*\s*$/.test(ports))throw new Error('Enter comma-separated TCP port numbers.');
        check.ports=[...new Set(ports.split(',').map(Number))];
        if(check.ports.length>64 || check.ports.some(p=>!Number.isInteger(p)||p<1||p>65535))throw new Error('Use 1–64 ports between 1 and 65535.');
      }
      if(action==='website'){if(!target)throw new Error('Choose an approved website first.');check.target=target;}
      if(isContent&&action!=='dependencies'){if(!content.trim())throw new Error('Enter content for this check.');check.content=content;}
      if(action==='dependencies'){if(!dependencyReady(dependency))throw new Error('Preview and approve the dependency scope first.');Object.assign(check,dependency);}
      if([...checks,check].reduce((sum,item)=>sum+new TextEncoder().encode(item.content||'').length,0)>1048576)throw new Error('Combined submissions exceed 1 MiB.');
      setChecks(list=>[...list,check]);setContent('');setDependency(emptyDependency());
    }catch(e){setError(e.message);}
  }
  async function start(event) {
    event.preventDefault();setBusy(true);setError('');setNotice('');
    const form=event.currentTarget,fields=new FormData(form);
    try {
      await api('/security-reviews',{workspace_id:me.workspace,name:fields.get('name'),authorized:fields.has('authorized'),ai_triage:fields.has('ai_triage'),checks});
      setChecks([]);form.reset();setNotice('Approved review started. Each check records its own coverage; requested AI triage follows the collected findings.');
      await refresh();
    }catch(e){setError(e.message);}finally{setBusy(false);}
  }
  return <>
    <section className="panel spaced"><h2>Coordinate a security review</h2><p>Choose the checks and targets for one approved run. Operators execute them in order, collect findings and optionally ask AI to prioritize follow-up tasks. This runs assessments and planning; it does not change device settings or website passwords.</p>
      {error&&<p className="notice error" role="alert">{error}</p>}{notice&&<p className="notice" role="status">{notice}</p>}
      <form className="operator-form" onSubmit={add}>
        <label>Check type<select value={action} onChange={event=>{const next=event.target.value;setAction(next);setTarget(next==='website'?(data.integrations.scan_hosts?.[0]||''):'127.0.0.1');}}>{Object.entries(labels).map(([value,label])=><option value={value} key={value}>{label}</option>)}</select></label>
        {isDevice&&<><label>Operator computer<select value={device} onChange={event=>setDevice(event.target.value)}><option value="local" disabled={!local}>This computer{local?'':' · unavailable on this host'}</option>{devices.map(d=><option value={d.id} key={d.id}>{d.label}</option>)}</select></label>{action==='device'&&<><label>Authorized private IP<input value={target} onChange={event=>setTarget(event.target.value)} required/></label><label>TCP ports<input value={ports} onChange={event=>setPorts(event.target.value)} required/></label></>}{action==='updates'&&<p className="fine">Read cached Windows Update counts and update-related restart status on the selected operator computer. Cache freshness is unverified; zero cached updates does not mean fully patched. No online catalog refresh, installation or restart. Remote clients require separate update-status consent and --allow-updates.</p>}{action==='posture'&&<p className="fine">Read-only Windows firewall, Defender and system-drive BitLocker status on the selected operator computer. Unsupported or denied checks remain unassessed.</p>}</>}
        {action==='website'&&<><label>Approved website<select value={target} onChange={event=>setTarget(event.target.value)} required><option value="">Choose a website</option>{(data.integrations.scan_hosts||[]).map(host=><option key={host}>{host}</option>)}</select></label>{!data.integrations.scan_hosts?.length&&<p>No website is in the configured assessment scope yet.</p>}</>}
        {isContent&&action!=='dependencies'&&<label>{'Python source'}<textarea value={content} onChange={event=>setContent(event.target.value)} rows={5} maxLength={100000} required/></label>}
        {action==='dependencies'&&<DependencyScope value={dependency} onChange={setDependency} disabled={busy}/>}
        <button className="button secondary" disabled={!canWrite||busy||checks.length>=6}>Add check to review</button>
      </form>
      <h3>Review scope · {checks.length}/6 checks</h3>
      {checks.length?<ol>{checks.map((check,index)=><li key={index}><strong>{labels[check.action]}</strong> · {check.target||`${check.content.length} characters`}{check.ports?` · ports ${check.ports.join(', ')}`:''}<button className="text-button" disabled={busy} onClick={()=>setChecks(list=>list.filter((_,i)=>i!==index))}>Remove check {index+1}</button></li>)}</ol>:<p>Add the assessments you want this run to cover.</p>}
      <p className="fine">Submitted source are processed in memory, excluded from stored review history and AI input. AI receives allowlisted finding summaries. Paired devices have a two-minute review response window; unavailable results stay unassessed. Account/vault actions remain separately approved.</p>
      <form className="operator-form" onSubmit={start}>
        <label>Review name<input name="name" required minLength={2} maxLength={80}/></label>
        <label className="check"><input name="authorized" type="checkbox" required/>I own or am authorized to assess every target in this review, and approve the listed checks.</label>
        <label className="check"><input name="ai_triage" type="checkbox" disabled={!data.integrations.groq_configured}/>After the checks, let AI prioritize up to 20 findings and create remediation tasks assigned to me.</label>
        {!data.integrations.groq_configured&&<p className="fine">Connect Groq to enable AI planning. The assessments can run independently.</p>}
        <button className="button" disabled={!canWrite||busy||reserved||!checks.length}>{busy?'Starting review…':'Approve and run review'}</button>
        {reserved&&<p role="status">Another review, assessment or agent workflow is active in this workspace.</p>}
      </form>
    </section>
    <section className="panel spaced"><h2>Review history</h2>{!reviews.length&&<p>No reviews have been run.</p>}{reviews.map(review=><article key={review.id} className="operation-record"><h3>{review.name} · {review.status}</h3><p className="fine">{new Date(review.created_at).toLocaleString()} · {review.finding_ids.length} recorded findings</p><ol>{review.checks.map(step=><ReviewStep key={step.index} step={step} scans={data.scans}/>)}</ol>{review.error&&<p role="status">{review.error}</p>}{review.triage_status&&<p>AI planning: {review.triage_status}{review.ai_triage?` · ${review.triage_count||0}/${review.finding_ids.length} findings included`:''}</p>}{review.finding_ids.length>0&&<button className="button secondary" onClick={()=>go('findings')}>Open workspace findings</button>}{review.agent_job&&<button className="button secondary" onClick={()=>go('agents')}>Open agent workflow</button>}{active(review)&&canWrite&&(review.created_by===me.id||me.role==='owner')&&<button className="button secondary" disabled={busy} onClick={async()=>{setBusy(true);setError('');try{await api('/security-reviews/'+review.id+'/cancel',{});await refresh();}catch(e){setError(e.message);}finally{setBusy(false);}}}>Cancel remaining review work</button>}<p className="fine">Finished checks and AI plans do not establish that findings were fixed. Review the evidence and run a new assessment after remediation.</p></article>)}</section>
  </>;
}
