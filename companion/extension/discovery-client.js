import {serviceOrigin} from './policy';
export async function discoveryRequest(connection,path,body,fetcher=(...args)=>globalThis.fetch(...args)){
  if(connection?.kind!=='discovery'||!/^[A-Za-z0-9_-]{40,100}$/.test(connection.token||''))throw new Error('Connect account discovery first.');
  if(!/^(context|revoke|observe|consents(?:\/[a-f0-9]{24}\/disable)?)$/.test(path))throw new Error('Unsupported discovery request.');
  const response=await fetcher(serviceOrigin(connection.origin)+'/api/companion/discovery/'+path,{method:body===undefined?'GET':'POST',credentials:'omit',redirect:'error',headers:{Authorization:'Bearer '+connection.token,...(body===undefined?{}:{'Content-Type':'application/json'})},...(body===undefined?{}:{body:JSON.stringify(body)}),signal:AbortSignal.timeout(10000)});
  if(!response.ok){let detail;try{detail=(await response.json()).detail;}catch{}throw new Error(typeof detail==='string'?detail:'Discovery connection unavailable. Reconnect before enabling sites.');}
  return response.json();
}
