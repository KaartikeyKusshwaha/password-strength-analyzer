import React,{useEffect,useState} from 'react';
export default function QuietChecks({browser,scope,onStatus,refreshAt}){
  const [sites,setSites]=useState([]),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  async function request(type,origin){const result=await browser.runtime.sendMessage({type,...(origin?{origin}:{})});if(!result?.ok)throw new Error(result?.error||'Monitoring controls are unavailable. Reload the companion.');setSites(result.sites||[]);}
  useEffect(()=>{if(browser.runtime?.sendMessage)request('site-monitor-status').catch(()=>{});},[refreshAt]);
  const current=sites.find(site=>site.origin===scope?.origin);
  useEffect(()=>{onStatus?.(current||null);},[sites,scope?.origin]);
  return <details><summary>Quiet site checks {current?'· enabled here':''}</summary>
    <p>Opt in per HTTPS site. Check its root headers on visits and roughly every 12 hours while the browser is open. Scheduled work can be delayed by sleep or browser limits. No cookies, page text, passwords, page paths or browsing-history upload. No cloud or AI request.</p>
    <p>Only chosen site origins and their latest header-check result/time are stored locally. A “!” badge means header observations; “?” means the check could not finish. Neither is a verdict that a site is safe.</p>
    {scope?.https&&!current&&<button className="secondary" disabled={busy} onClick={async()=>{setBusy(true);setError('');try{if(!await browser.permissions.request({origins:[scope.permission]}))throw new Error('Website access was declined. Quiet checks remain off.');await request('site-monitor-enable',scope.origin);}catch(e){setError(e.message);}finally{setBusy(false);}}}>{busy?'Checking…':'Enable quiet checks for this site'}</button>}
    {current&&<><p role="status">{current.state==='issues'?`${current.result?.actions.length||0} header observations`:current.state==='clear'?'No listed header issues in the last check':'Last check could not finish'}{current.at?` · ${new Date(current.at).toLocaleString()}`:''}</p>{current.result?.actions.map(action=><details key={action.id}><summary>{action.title}</summary><p>{action.detail}</p></details>)}</>}
    {sites.length>0&&<details><summary>Manage {sites.length} chosen sites</summary>{sites.map(site=><div key={site.origin}><p>{site.origin}</p><button className="secondary" disabled={busy} onClick={async()=>{setBusy(true);setError('');try{await request('site-monitor-disable',site.origin);}catch(e){setError(e.message);}finally{setBusy(false);}}}>Stop quiet checks for {site.origin}</button></div>)}<p className="fine">Stopping checks deletes their saved result. Existing host access for saving/filling is retained; you can remove it in browser extension settings.</p></details>}
    {error&&<p role="alert" className="error">{error}</p>}
  </details>;
}
