import LeaseHistory from './LeaseHistory';
import HandoffHistory from './HandoffHistory';
import React,{useEffect,useState} from 'react';
import {api} from './api';

export default function WorkflowHistory(){
  const [runs,setRuns]=useState([]),[error,setError]=useState(''),[report,setReport]=useState(null),[busy,setBusy]=useState(false);
  async function refresh(){setError('');setBusy(true);try{const result=await api('/access-workflows');setRuns(result.workflows||[]);}catch(e){setError(e.message);}finally{setBusy(false);}}
  useEffect(()=>{refresh();},[]);
  return <><LeaseHistory/><HandoffHistory/><section className="panel"><h2>Offboarding history</h2><p>Prepare and approve everyday offboarding from the extension. This control room retains progress and evidence for review.</p><button className="button secondary" disabled={busy} onClick={refresh}>Refresh offboarding history</button>
    {!runs.length&&!error&&<p>No offboarding plans recorded.</p>}
    {runs.map(run=><div className="member-row" key={run.id}><p>{run.plan.dry_run?'Preview':'Vault offboarding'} · {run.status} · {run.created_at}{run.rechecks?.some(check=>check.status==='attention')?' · Recheck needs attention':''}</p><button className="button secondary" disabled={busy} onClick={async()=>{setBusy(true);setError('');try{setReport(await api('/access-workflows/'+run.id+'/report'));}catch(e){setError(e.message);}finally{setBusy(false);}}}>Review evidence: {run.id.slice(0,8)}</button></div>)}
    {report&&<><p className="notice">{report.limitations}</p><label>Vault offboarding evidence<textarea readOnly rows={16} value={JSON.stringify(report,null,2)}/></label><button className="button secondary" onClick={()=>{const blob=new Blob([JSON.stringify(report,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download='sentinelops-offboarding-'+report.workflow+'.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}}>Download evidence JSON</button><button className="button secondary" onClick={()=>setReport(null)}>Close evidence</button></>}
    {error&&<p role="alert" className="notice error">{error}</p>}
  </section></>;
}
