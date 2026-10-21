import React,{useEffect,useState} from 'react';
import {startCloudConnection,finishCloudConnection,cancelCloudConnection} from './cloud-connect';
export default function CloudConnect({onConnected,browser=chrome}){
  const [pending,setPending]=useState(null),[busy,setBusy]=useState(false),[error,setError]=useState('');
  useEffect(()=>{let live=true;browser.storage.local.get('cloudConnect').then(async result=>{
    if(!live)return;setPending(result.cloudConnect||null);
    if(result.cloudConnect&&result.cloudConnect.expires*1000>Date.now()){
      setBusy(true);try{const connection=await finishCloudConnection(browser);if(live&&connection)onConnected(connection);}catch(e){if(live)setError(e.message);}finally{if(live)setBusy(false);}
    }
  });return()=>{live=false;};},[]);
  return <section><h2>Connect your cloud vault</h2><p>Sign in and approve one vault. No tokens to copy. Your master passphrase stays in this extension.</p>{pending?<><p>Compare code <strong>{pending.code}</strong> on the approval page.</p><button disabled={busy} onClick={async()=>{setBusy(true);setError('');try{const connection=await finishCloudConnection(browser);if(connection)onConnected(connection);else setError('Still waiting for your approval in the sign-in tab.');}catch(e){setError(e.message);}finally{setBusy(false);}}}>Finish connection</button><button className="secondary" disabled={busy} onClick={async()=>{setBusy(true);setError('');try{await cancelCloudConnection(browser);setPending(null);}catch(e){setError(e.message);}finally{setBusy(false);}}}>Cancel connection request</button></>:<button disabled={busy} onClick={async()=>{setBusy(true);setError('');try{setPending(await startCloudConnection(browser));}catch(e){setError(e.message);}finally{setBusy(false);}}}>{busy?'Opening…':'Sign in and connect'}</button>}{error&&<p role="alert" className="error">{error}</p>}</section>;
}
