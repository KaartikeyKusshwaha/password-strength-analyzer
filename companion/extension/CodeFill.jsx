import React,{useState} from 'react';
import {fillSavedCode} from './autofill-client';
import manifest from './public/manifest.json';

export default function CodeFill({entry,active,session,onUpdated,browser=chrome}){
  const [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
  if(!active)return null;
  async function act(work){setBusy(true);setError('');setNotice('');try{await work();}catch{setError('Code action could not finish. Check the website, current vault access and code expiry; no form was submitted.');}finally{setBusy(false);}}
  return <div>{entry.autofill_origin===active.origin?<button disabled={busy} onClick={()=>act(async()=>{await fillSavedCode(browser,session,entry.id,active,manifest.version);setNotice('Verification code filled. Review the website before submitting.');})}>{busy?'Checking…':'Fill verification code'}</button>:<details><summary>Enable filling for this website</summary><p>Link “{entry.title}” to <strong>{active.origin}</strong> only if this authenticator belongs to that account. Issuer names are never used to guess a website.</p>{entry.autofill_origin&&<p>This replaces its current link to {entry.autofill_origin}.</p>}<button disabled={busy} onClick={()=>act(async()=>{await session.bindCode(entry.id,active.origin);onUpdated();setNotice('Exact website link encrypted and saved.');})}>Confirm website link</button></details>}
    {entry.autofill_origin&&<><p className="fine">Linked website: {entry.autofill_origin}</p><button className="secondary" disabled={busy} onClick={()=>act(async()=>{await session.unlinkCode(entry.id);onUpdated();setNotice('Website link removed. Code filling disabled for this entry.');})}>Disable code filling</button></>}
    {error&&<p role="alert" className="error">{error}</p>}{notice&&<p role="status" className="notice">{notice}</p>}
  </div>;
}
