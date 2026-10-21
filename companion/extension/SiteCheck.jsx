import React,{useEffect,useState} from 'react';
import {websiteScope,checkWebsite} from './site-check';

export default function SiteCheck({browser=chrome}) {
  const [scope,setScope]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false),[result,setResult]=useState(null);
  useEffect(()=>{browser.tabs.query({active:true,currentWindow:true}).then(tabs=>{try{setScope(websiteScope(tabs[0]?.url));}catch{setError('Open a public website to check it.');}}).catch(()=>setError('Cannot read the active website.'));},[]);
  async function run(){setBusy(true);setError('');setResult(null);try{
    // A user click grants access only to this exact origin. Never request all sites.
    if(scope.https){
      const granted=await browser.permissions.request({origins:[scope.permission]});
      if(!granted)throw new Error('Website access was declined. Nothing was checked.');
    }
    const tabs=await browser.tabs.query({active:true,currentWindow:true});
    if(websiteScope(tabs[0]?.url).origin!==scope.origin)throw new Error('The active website changed. Reopen the companion before checking.');
    setResult(await checkWebsite(scope));
  }catch(error){setError(error.message);}finally{setBusy(false);}}
  return <section aria-label="Website security check"><strong>{busy?'Checking this website…':result?(result.actions.length?`${result.actions.length} things to review`:'No issues found in this header check'):'Check the site you are visiting'}</strong>
    {scope&&<p className="fine">{scope.origin} · Runs in browser</p>}
    <button disabled={!scope||busy} onClick={run}>{busy?'Checking…':'Check this site'}</button>
    {error&&<p role={scope?'alert':'status'} className={scope?'error':'fine'}>{error}</p>}
    {result&&<><p className="fine">{result.coverage} {result.status&&`HTTP ${result.status}.`} This is not a verdict that a site is safe.</p>{result.actions.map(action=><details key={action.id}><summary>{action.title}</summary><p>{action.detail}</p><p className="fine">Only the site owner can change its server headers. No repair was performed.</p></details>)}</>}
    <details><summary>Check my device</summary><p>Needs device helper · Your browser cannot inspect device ports, firewall or installed software. Use Connect device helper in the security assistant below. Existing connections are managed in the control room.</p></details>
  </section>;
}
