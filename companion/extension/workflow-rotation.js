import {accessRequest} from './access-client';
import {rotateTeamVault} from '../../frontend/src/sharing-crypto';

export async function rotateConnectedVault(access,session,workflow,vault,request=accessRequest){
  const config=session.config,material=session.material;
  if(!/^[a-f0-9]{24}$/.test(workflow)||!/^[a-f0-9]{24}$/.test(vault)||material?.kind!=='shared'||config?.vaultId!==vault||config.origin!==access.origin)throw new Error('Select and unlock the matching shared vault from this service first.');
  return session.external(async({active,signal})=>{
    const path='workflows/'+workflow+'/vaults/'+vault+'/rotation',options={vaultToken:config.token,signal};
    const context=await request(access,path,undefined,undefined,options);active();
    if(context.team.id!==vault||context.team.epoch!==material.epoch||context.team.owner!==material.identity.user)throw new Error('Vault access changed. Lock and unlock it before rotating.');
    const body=await rotateTeamVault(context.team,material.identity,material.trusted,context.directory);active();
    return request(access,path,body,undefined,options);
  });
}
