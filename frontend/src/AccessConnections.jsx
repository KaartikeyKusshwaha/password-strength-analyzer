import React,{useEffect,useState} from 'react';
import {api} from './api';
export default function AccessConnections(){
  const [connections,setConnections]=useState([]),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  async function load(){const value=await api('/extension-capabilities');setConnections(value.connections||[]);}
  useEffect(()=>{load().catch(e=>setError(e.message));},[]);
  return <section className="panel"><h2>Access and discovery connections</h2><p>Revoke workflow or opt-in discovery permissions here, including connections forgotten on another browser. Vault and scanner connections remain separate. Revoking a connection does not cancel an already approved workflow.</p>
    {connections.map(item=><div className="member-row" key={item.id}><p>{item.kind==='access'?'Access workflows':'Opt-in account discovery'} · Expires {new Date(item.expires*1000).toLocaleString()}</p><button className="button secondary" disabled={busy} onClick={async()=>{setBusy(true);setError('');try{await api('/extension-capabilities/'+item.kind+'/'+item.id+'/revoke',{});await load();}catch(e){setError(e.message);}finally{setBusy(false);}}}>Revoke {item.kind} connection</button></div>)}
    {!connections.length&&!error&&<p>No active access or discovery connections.</p>}{error&&<p role="alert" className="notice error">{error}</p>}
  </section>;
}
