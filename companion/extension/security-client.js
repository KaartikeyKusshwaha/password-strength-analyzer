import {serviceOrigin} from './policy';
export async function securityRequest(connection,path,body,fetcher=(...args)=>globalThis.fetch(...args)){
  if(!connection||connection.kind!=='security'||!/^\/(context|revoke|inventory-preview|operations(?:\/[a-f0-9]{24}(?:\/cancel)?)?)$/.test(path))throw new Error('A separate security connection is required.');
  const response=await fetcher(serviceOrigin(connection.origin)+'/api/companion/security'+path,{method:body===undefined?'GET':'POST',credentials:'omit',redirect:'error',headers:{Authorization:'Bearer '+connection.token,...(body===undefined?{}:{'Content-Type':'application/json'})},...(body===undefined?{}:{body:JSON.stringify(body)}),signal:AbortSignal.timeout(15000)});
  if(!response.ok)throw new Error(response.status===401||response.status===403?'Security access expired or was removed. Reconnect your security agents.':'The check could not start or finish. Review its approved target and device connection.');
  return response.json();
}
