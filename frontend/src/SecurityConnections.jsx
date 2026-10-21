import React,{useEffect,useState} from 'react';
import {api} from './api';
export default function SecurityConnections(){
  const [connections,setConnections]=useState([]),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  async function refresh(){const value=await api('/security-connections');if(!Array.isArray(value.connections))throw new Error('Unexpected security-connection response.');setConnections(value.connections);}
  useEffect(()=>{refresh().catch(()=>setError('Could not load security-agent connections.'));},[]);
  return <section className="panel spaced"><h2>Extension security-agent access</h2><p>Separate from encrypted vault connections. These connections can request approved assessments and read the requester’s results in this workspace. They cannot unlock vaults or approve repairs.</p>{connections.length?connections.map(connection=><article key={connection.id}><p>{connection.origin} · expires {new Date(connection.expires*1000).toLocaleString()}</p><button className="button secondary" disabled={busy} onClick={async()=>{setBusy(true);setError('');try{await api('/security-connections/'+connection.id+'/revoke',{});await refresh();}catch(e){setError(e.message);}finally{setBusy(false);}}}>Revoke security-agent access</button></article>):<p>No active security-agent connections.</p>}{error&&<p role="alert" className="notice error">{error}</p>}</section>;
}
