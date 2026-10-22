import {accessRequest} from './access-client';
import {canonical,verifyTeam,ownershipStateDigest,prepareOwnershipProposal,acceptOwnershipTransfer} from '../../frontend/src/sharing-crypto';

function selected(access,session){
 const config=session?.config,material=session?.material;
 if(material?.kind!=='shared'||!/^[a-f0-9]{24}$/.test(config?.vaultId||'')||config.origin!==access.origin)throw new Error('Select and unlock the matching shared vault from this service first.');
 return {config,material};
}

async function perform(access,session,work,request){
 const {config,material}=selected(access,session),revision=session.revision,entries=session.entries;
 if(session.pending?.size)throw new Error('Wait for the current vault action before changing ownership.');
 return session.external(async({active,signal})=>{
  function unchanged(){active();if(session.revision!==revision||session.entries!==entries||session.pending?.size>1)throw new Error('Vault changed locally. Reload ownership before continuing.');}
  const path='vaults/'+config.vaultId+'/ownership',options={vaultToken:config.token,signal};
  const context=await request(access,path,undefined,undefined,options);unchanged();
  if(context.team.id!==config.vaultId||context.team.epoch!==material.epoch||context.team.revision!==revision)throw new Error('Vault access changed. Lock and unlock before continuing.');
  await verifyTeam(context.team,material.identity,material.trusted);unchanged();
  return work({context,path,options,material,unchanged});
 });
}

export async function loadConnectedOwnership(access,session,request=accessRequest){return perform(access,session,({context})=>context,request);}

export async function changeConnectedOwnership(access,session,snapshot,mode,target,formerRole='removed',request=accessRequest){
 if(!['propose','accept','cancel'].includes(mode))throw new Error('Unsupported ownership action.');
 let attempted=false;
 try{return await perform(access,session,async({context,path,options,material,unchanged})=>{
  if(!snapshot?.team||await ownershipStateDigest(snapshot.team)!==await ownershipStateDigest(context.team))throw new Error('Ownership evidence changed. Reload and review before continuing.');unchanged();
  let body,suffix='';
  if(mode==='propose'){
   const recipient=context.directory.find(person=>person.id===target);
   if(!recipient)throw new Error('Choose a current accepted teammate.');
   body=await prepareOwnershipProposal(context.team,material.identity,recipient,formerRole);
  }else{
   if(!snapshot.proposal?.id||snapshot.proposal.id!==context.proposal?.id||context.proposal.status!=='pending'||canonical(snapshot.proposal.document)!==canonical(context.proposal.document)||snapshot.proposal.signature!==context.proposal.signature)throw new Error('Ownership proposal changed or stopped. Reload it.');
   if(mode==='accept'){body=await acceptOwnershipTransfer(context.team,material.identity,material.trusted,context.proposal,context.directory);suffix='/accept';}
   else{if(!/^[a-f0-9]{24}$/.test(context.proposal.id))throw new Error('Invalid ownership proposal.');body={};suffix='/'+context.proposal.id+'/cancel';}
  }
  unchanged();
  attempted=mode==='accept';const result=await request(access,path+suffix,body,undefined,options);unchanged();return result;
 },request);}
 catch(error){if(attempted)error.ownershipAttempted=true;throw error;}
 finally{if(attempted)session.lock();}
}
