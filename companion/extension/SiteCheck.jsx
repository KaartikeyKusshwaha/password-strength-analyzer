import React,{useEffect,useState} from 'react';
import {websiteScope,checkWebsite} from './site-check';
import QuietChecks from './QuietChecks';

export default function SiteCheck({browser=chrome}) {
  const [scope,setScope]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false),[result,setResult]=useState(null),[monitored,setMonitored]=useState(null);
  useEffect(()=>{browser.tabs.query({active:true,currentWindow:true}).then(tabs=>{try{setScope(websiteScope(tabs[0]?.url));}catch{setError('Open a public website to check it.');}}).catch(()=>setError('Cannot read the active website.'));},[]);
  async function run(){setBusy(true);setError('');setResult(null);try{
    // A user click grants access only to this exact origin. Never request all sites.
    if(scope.https){
      const granted=await browser.permissions.request({origins:[scope.permission]});
      if(!granted)throw new Error('Website access was declined. Nothing was checked.');
    }
    const tabs=await browser.tabs.query({active:true,currentWindow:true});
    if(websiteScope(tabs[0]?.url).origin!==scope.origin)throw new Error('The active website changed. Reopen the companion before checking.');
    if(monitored){
      const response=await browser.runtime.sendMessage({type:'site-monitor-recheck',origin:scope.origin});
      if(!response?.ok)throw new Error(response?.error||'Quiet check could not finish. Reopen the companion.');
      const latest=response.sites.find(site=>site.origin===scope.origin);setMonitored(latest||null);
      if(!latest?.result)throw new Error('The site could not be assessed. No safety verdict was produced.');
      setResult(latest.result);
    }else setResult(await checkWebsite(scope));
  }catch(error){setError(error.message);}finally{setBusy(false);}}
  const displayed=result||(!error?monitored?.result:null);
  return <section aria-label="Website security check"><strong>{busy?'Checking this website…':displayed?(displayed.actions.length?`${displayed.actions.length} things to review`:'No issues found in this header check'):monitored?.state==='unassessed'?'Quiet check could not finish; review or recheck.':'Check the site you are visiting'}</strong>
    {scope&&<p className="fine">{scope.origin} · Runs in browser</p>}
    <button disabled={!scope||busy} onClick={run}>{busy?'Checking…':'Check this site'}</button>
    {error&&<p role={scope?'alert':'status'} className={scope?'error':'fine'}>{error}</p>}
    {displayed&&<><p className="fine">{displayed.coverage} {displayed.status&&`HTTP ${displayed.status}.`} This is not a verdict that a site is safe.</p>{displayed.actions.map(action=><details key={action.id}><summary>{action.title}</summary><p>{action.detail}</p><p className="fine">Only the site owner can change its server headers. No repair was performed.</p></details>)}</>}
    <QuietChecks browser={browser} scope={scope} onStatus={setMonitored} refreshAt={monitored?.at}/>
  </section>;
}
