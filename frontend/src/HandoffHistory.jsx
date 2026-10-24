import React,{useEffect,useState} from 'react';
import {api} from './api';
export default function HandoffHistory(){
 const [records,setRecords]=useState([]),[error,setError]=useState(''),[selected,setSelected]=useState(null);
 async function refresh(){setError('');try{setRecords((await api('/handoffs')).handoffs||[]);}catch(e){setError(e.message);}}
 useEffect(()=>{refresh();},[]);
 return <section className="panel"><h2>Client handoff receipts</h2><p>Prepare, approve and sign off in the extension. Receipts retain the reviewed snapshot; they do not certify external access or device wiping.</p><button className="button secondary" onClick={refresh}>Refresh handoff history</button>{records.map(row=><div className="member-row" key={row.id}><p>{row.kind.replaceAll('_',' ')} · {row.status.replaceAll('_',' ')} · {row.created_at}{row.evidence_changed_since_signoff?' · Evidence changed since sign-off':''}</p><button className="button secondary" onClick={()=>setSelected(row)}>Review handoff {row.id.slice(0,8)}</button></div>)}{selected&&<><label>Handoff evidence JSON<textarea readOnly rows={12} value={JSON.stringify(selected,null,2)}/></label><button className="button secondary" onClick={()=>setSelected(null)}>Close handoff evidence</button></>}{!records.length&&!error&&<p>No client handoffs recorded.</p>}{error&&<p role="alert">{error}</p>}</section>;
}
