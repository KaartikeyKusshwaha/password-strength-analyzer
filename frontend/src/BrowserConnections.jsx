import {useEffect,useRef,useState} from 'react';
import {api} from './api';

export default function BrowserConnections({refreshKey=0}){
  const [data,setData]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  const current=useRef(0),mounted=useRef(false);
  async function load(){
    const request=++current.current;setBusy(true);
    try{const next=await api('/companions');if(mounted.current && request===current.current){setData(next);setError('');}}
    catch(error){if(mounted.current && request===current.current)setError(error.message);}
    finally{if(mounted.current && request===current.current)setBusy(false);}
  }
  useEffect(()=>{mounted.current=true;load();const timer=setInterval(()=>{if(!document.hidden)load();},15000);return()=>{mounted.current=false;current.current++;clearInterval(timer);};},[refreshKey]);
  return <section className="spaced" aria-label="Your browser connection reports">
    <h3>Connection reports</h3><p className="fine">Last successful encrypted-vault contact, recorded at most once a minute. A reported version does not prove installation, an unlocked vault or working autofill. No website history, passwords or vault contents are collected for this report.</p>
    <button className="button secondary" disabled={busy} onClick={load}>Refresh browser connections</button>
    {error&&<p className="notice error" role="alert">{error}{data?' Displayed connection reports may be out of date.':''}</p>}
    {!data?<p>{error?'Connection reports could not be loaded.':'Loading connection reports…'}</p>:<>
      <p className="fine">{data.download_version?'Downloadable companion: '+data.download_version:'Downloadable companion version could not be verified.'}</p>
      {!data.connections.length&&<p>No active browser tokens. Create a private connection below.</p>}
      {data.connections.map(item=><article className="operation-record" key={item.id}><strong>{item.label}</strong><p className="fine">{item.kind==='shared'?'Shared vault':'Personal vault'} · Token expires {new Date(item.expires*1000).toLocaleString()}</p>
        <p>{item.last_contact?'Last vault contact: '+new Date(item.last_contact*1000).toLocaleString():'No successful vault contact recorded yet.'}</p>
        <p className="fine">{item.reported_version?'Client reports version '+item.reported_version+(data.download_version?(item.reported_version===data.download_version?' · Matches the downloadable build.':' · Differs from the downloadable build. Check the extension version, reload it after updating, then reopen its popup.'):''):'Version not reported. Older companions can connect without reporting a version; this does not prove that they are offline.'}</p>
      </article>)}
    </>}
  </section>;
}
