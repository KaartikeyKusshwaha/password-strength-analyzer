import {accessRequest} from './access-client';
import {canonical,verifyTeam,ownershipStateDigest} from '../../frontend/src/sharing-crypto';

export async function signFreelancerVault(connection,session,draft,request=accessRequest){
 const config=session?.config,material=session?.material,revision=session?.revision,entries=session?.entries;
 const item=draft?.plan?.vaults.find(item=>item.vault===config?.vaultId);
 if(material?.kind!=='shared'||config.origin!==connection.origin||!item||draft.status!=='pending'||draft.deadline*1000<=Date.now())throw new Error('Select and unlock one of this pending invitation’s client vaults.');
 if(session.pending?.size)throw new Error('Wait for the current vault action before signing an invitation.');
 return session.external(async({active,signal})=>{
  function unchanged(){active();if(session.entries!==entries||session.revision!==revision||session.pending?.size>1)throw new Error('Vault changed locally. Prepare the invitation again.');}
  const path='invitations/'+draft.id+'/vaults/'+config.vaultId;
  const context=await request(connection,path,undefined,undefined,{vaultToken:config.token,signal});unchanged();
  if(context.draft.plan_digest!==draft.plan_digest||canonical(context.draft.plan)!==canonical(draft.plan)||context.team.id!==config.vaultId||context.team.epoch!==material.epoch||context.team.revision!==revision||context.team.owner!==material.identity.user||context.recipient.id!==draft.plan.person||context.recipient.fingerprint!==draft.plan.recipient_fingerprint)throw new Error('Invitation scope or identity changed. Prepare a new draft.');
  await verifyTeam(context.team,material.identity,material.trusted);unchanged();
  if(await ownershipStateDigest(context.team)!==item.state_digest)throw new Error('Client vault contents or membership changed. Prepare a new draft.');unchanged();
  const grant=await material.handle.invite(context.recipient,draft.plan.role);unchanged();
  return {vault_id:config.vaultId,token:config.token,grant};
 });
}
