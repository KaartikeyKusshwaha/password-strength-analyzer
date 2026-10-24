import {useState} from 'react';
import {serviceOrigin} from './policy';

export const TOOLS=[['passwords','Passwords & vaults'],['authenticator','Two-factor authentication'],['vulnerabilities','Vulnerability checks']];
export function toolUrl(origin,tool) {
  if(!TOOLS.some(([id])=>id===tool))throw new Error('Unsupported security tool');
  return serviceOrigin(origin)+'/#tool='+tool;
}
export default function SecurityHub({origin='http://127.0.0.1:8110',browser=chrome}) {
  const [error,setError]=useState('');
  return <section className="security-hub"><strong>Three tools. One security service.</strong><div className="hub-tools">{TOOLS.map(([id,title])=><button type="button" className="secondary" key={id} onClick={async()=>{setError('');try{await browser.tabs.create({url:toolUrl(origin,id)});}catch{setError('Cannot open SentinelOps. Check the app address and keep the service running.');}}}>{title}</button>)}</div><p className="fine">Open the connected service to run agents. Password checks, saving, autofill and authenticator codes remain private vault operations.</p>{error&&<p role="alert" className="error">{error}</p>}</section>;
}
