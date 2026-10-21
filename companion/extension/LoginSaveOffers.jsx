import React,{useEffect,useState} from 'react';
export default function LoginSaveOffers({browser,origin}){
  const [sites,setSites]=useState([]),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  async function request(type,site){const result=await browser.runtime.sendMessage({type,...(site?{origin:site}:{})});if(!result?.ok)throw new Error(result?.error||'Save-offer controls unavailable. Reload the companion.');setSites(result.sites||[]);}
  useEffect(()=>{request('login-offer-status').catch(()=>{});},[]);
  const enabled=sites.includes(origin);
  return <details><summary>Offer to save after login {enabled?'· enabled here':''}</summary>
    <p>Off by default. For each chosen HTTPS site, a trusted login submission can keep its username and password only in extension-worker memory for up to three minutes. When the password form disappears, an offer appears. The extension cannot prove the website accepted the login or compare it with a locked vault.</p>
    <p>No automatic saving, AI disclosure or disk storage of this draft. Dismissal, expiry, leaving the site or a worker restart drops it. You still unlock and confirm encrypted saving in the private extension window.</p>
    {origin?.startsWith('https://')&&!enabled&&<button className="secondary" disabled={busy} onClick={async()=>{setBusy(true);setError('');try{if(!await browser.permissions.request({origins:[origin+'/*']}))throw new Error('Site access declined. Save offers stay off.');await request('login-offer-enable',origin);}catch(e){setError(e.message);}finally{setBusy(false);}}}>Enable login save offers for this site</button>}
    {sites.map(site=><p key={site}>{site}<button className="secondary" disabled={busy} onClick={async()=>{setBusy(true);setError('');try{await request('login-offer-disable',site);}catch(e){setError(e.message);}finally{setBusy(false);}}}>Stop save offers for {site}</button></p>)}
    {error&&<p role="alert" className="error">{error}</p>}
  </details>;
}
