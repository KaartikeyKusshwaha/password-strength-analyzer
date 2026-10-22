import React,{useEffect,useState} from 'react';
import {api} from './api';
export default function LeaseHistory(){
 const [records,setRecords]=useState([]),[error,setError]=useState('');
 async function refresh(){setError('');try{setRecords((await api('/access-leases')).leases||[]);}catch(e){setError(e.message);}}
 useEffect(()=>{refresh();},[]);
 return <section className="panel"><h2>Access expiry history</h2><p>Configure and approve freelancer expiry or scheduled departures in the extension. This view retains the policy and linked-run outcome.</p><button className="button secondary" onClick={refresh}>Refresh access expiry history</button>{records.map(row=><div className="member-row" key={row.id}><p>{row.client_name||'Client'} · {row.person_email||'Former member'} · {row.status.replaceAll('_',' ')} · {new Date(row.plan.expires_at*1000).toLocaleString()}{row.workflow_status?' · '+row.workflow_status.replaceAll('_',' '):''}</p>{row.reason&&<p role="alert">{row.reason}</p>}</div>)}{!records.length&&!error&&<p>No expiry policies recorded.</p>}{error&&<p role="alert">{error}</p>}</section>;
}
