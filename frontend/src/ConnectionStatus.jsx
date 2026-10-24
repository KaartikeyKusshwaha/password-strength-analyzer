import {useState,useSyncExternalStore} from 'react';
import {api} from './api';
import {connectionSnapshot,subscribeConnection} from './connection-state';
const labels={unknown:'Checking backend',available:'Backend reachable',unavailable:'Backend unavailable',error:'Backend error'};
export default function ConnectionStatus(){
  const state=useSyncExternalStore(subscribeConnection,connectionSnapshot,connectionSnapshot);
  const [checking,setChecking]=useState(false);
  return <span className="local-tag" data-state={state} role="status" aria-live="polite" title="Based on the most recent app request. For a local installation, keep the SentinelOps server running.">
    <span className={'status-light'+(state==='available'?' on':'')} aria-hidden="true"/>
    {labels[state]}
    {(state==='unavailable'||state==='error') && <button className="text-button" disabled={checking} onClick={async()=>{setChecking(true);try{await api('/status');}catch{/* The API updates the shared connection state. */}finally{setChecking(false);}}}>{checking?'Checking…':'Retry connection'}</button>}
  </span>;
}
