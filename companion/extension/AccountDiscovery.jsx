import React,{useEffect,useState} from 'react';
import CloudConnect from './CloudConnect';

export default function AccountDiscovery({browser=chrome,active}){
  const [value,setValue]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false),[client,setClient]=useState(''),[label,setLabel]=useState('');
  async function send(message){const result=await browser.runtime.sendMessage(message);if(!result?.ok)throw new Error(result?.error||'Discovery controls are unavailable. Reload the companion.');return result;}
  async function load(){setValue(await send({type:'discovery-status'}));}
  useEffect(()=>{let live=true;browser.storage.local.get('discoveryConnection').then(saved=>saved.discoveryConnection?send({type:'discovery-status'}):{ok:true,connection:false,sites:[],context:null}).then(result=>{if(live)setValue(result);}).catch(e=>{if(live)setError(e.message);});return()=>{live=false;};},[]);
  async function run(work){setBusy(true);setError('');try{await work();await load();}catch(e){setError(e.message);const local=await browser.storage.local.get(['discoveryConnection','discoverySites']);setValue(previous=>previous?{...previous,connection:!!local.discoveryConnection,sites:Array.isArray(local.discoverySites)?local.discoverySites:[]}:previous);}finally{setBusy(false);}}
  return <details><summary>Account discovery · opt in per site</summary><p>Record only this site's domain and your chosen account nickname in the client access map. Login attempts are observations, not proof of successful sign-in. Passwords, page content and other browsing history are never recorded by discovery.</p>
    {value&&!value.connection?<CloudConnect browser={browser} scope="discovery" onConnected={()=>load().catch(e=>setError(e.message))}/>:value?.connection?<>
      <form onSubmit={event=>{event.preventDefault();run(async()=>{if(!active?.origin)throw new Error('Open a supported HTTPS website first.');const allowed=await browser.permissions.request({origins:[active.origin+'/*']});if(!allowed)throw new Error('Site access was declined.');await send({type:'discovery-enable',origin:active.origin,client,label});});}}>
        <p>{active?.origin||'Open an HTTPS website to enable discovery.'}</p><label>Client for this site<select required value={client} onChange={e=>setClient(e.target.value)}><option value="">Choose client</option>{value.context.clients.map(item=><option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
        <label>Account nickname<input required maxLength={100} value={label} onChange={e=>setLabel(e.target.value)} placeholder="Client's social account"/></label><button disabled={busy||!active?.origin||!client||!label.trim()}>Enable discovery on this site</button>
      </form>
      {value.sites.map(item=><p key={item.id}>{item.domain} · {item.account_label} <button className="secondary" disabled={busy} onClick={()=>run(()=>send({type:'discovery-disable',id:item.id}))}>Stop recording {item.domain}</button></p>)}
      <button className="secondary" disabled={busy} onClick={()=>run(()=>send({type:'discovery-disconnect'}))}>Disconnect account discovery</button>
      <p className="fine">Stopping collection preserves previously reported records. An owner can retire those records in Clients & Access. Removing browser host permission pauses all local discovery sites until explicitly enabled again.</p>
    </>:!error?<p>Loading discovery controls…</p>:null}
    {error&&<><p role="alert" className="error">{error}</p><button className="secondary" disabled={busy} onClick={async()=>{await browser.storage.local.remove('discoveryConnection');await browser.storage.local.set({discoverySites:[]});setValue({connection:false,sites:[],context:null});setError('');}}>Forget local discovery connection</button><p className="fine">This stops local collection. Any unexpired server grant can be revoked from Connections in the control room.</p></>}
  </details>;
}
