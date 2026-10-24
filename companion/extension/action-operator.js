import {stageChange,finishChange} from '../../frontend/src/credential-changes';
import {generatePassword} from '../../frontend/src/lab';
import {validOrigin} from '../../frontend/src/vault-crypto';
import {isArchived} from '../../frontend/src/entry-history';

// Deterministic local operator. Approved plans are decrypted only after vault unlock.
// It never clicks website buttons, submits forms, or claims independent success.
export class AccountOperator {
  constructor(session,browser) {this.session=session;this.browser=browser;this.action=null;this.plan=null;this.lease=null;}
  async select(job,resume=false) {
    const generation=this.session.generation;
    await this.session.refresh();const plan=await this.session.actionPlan(job);this.session.active(generation);
    const claim=await this.session.request({resume},'/actions/'+job.id+'/claim');
    this.session.active(generation);
    // The service cannot substitute a new encrypted approval between preview and claim.
    if(JSON.stringify(claim.action.manifest)!==JSON.stringify(job.manifest))throw new Error('The approval changed. Cancel and review it again.');
    this.action=claim.action;this.plan=plan;this.lease=claim.lease;
    await this.browser.storage.session.set({accountAction:{id:job.id,lease:claim.lease}});
  }
  async stageApproved(job){
    await this.select(job);
    for(let index=0;index<this.plan.items.length;index++)await this.stage(index);
    return this.action;
  }
  async restore(jobs) {
    if(!this.browser.storage.session)return false;
    const saved=(await this.browser.storage.session.get('accountAction')).accountAction;
    if(!saved)return false;
    const job=jobs.find(a=>a.id===saved.id && ['running','awaiting_confirmation'].includes(a.status));
    if(!job)return false;
    this.plan=await this.session.actionPlan(job);this.action=job;this.lease=saved.lease;return true;
  }
  async fresh() {
    const generation=this.session.generation;
    if(!this.action || !this.lease)throw new Error('Choose an approved action first.');
    const current=(await this.session.actions()).find(a=>a.id===this.action.id);
    this.session.active(generation);
    if(!current || !['running','awaiting_confirmation'].includes(current.status))throw new Error('This action stopped or its lease expired. Review it before resuming.');
    this.plan=await this.session.actionPlan(current);this.session.active(generation);this.action=current;
    return generation;
  }
  item(index) {
    const approved=this.plan?.items[index],entry=this.session.entries?.find(e=>e.id===approved?.entry_id && e.type==='login' && !isArchived(e) && e.origin===approved.origin);
    if(!entry)throw new Error('The approved login changed or is unavailable. Review a fresh plan.');
    this.session.permitted('save',approved.origin);this.session.permitted('fill',approved.origin);
    return {approved,entry};
  }
  async report(index,state,reason='') {
    const value=await this.session.request({lease:this.lease,index,state,reason},'/actions/'+this.action.id+'/result');
    this.action={...this.action,status:value.status,items:value.items};return value;
  }
  async stage(index) {
    const generation=await this.fresh(),{entry}=this.item(index),state=this.action.items[index]?.state;
    if(['confirmed_by_user','discarded'].includes(state))throw new Error('This account action has finished.');
    if(entry.change_receipt?.action_id===this.action.id)throw new Error('This password was already confirmed. Record that outcome instead of staging another.');
    if(!entry.pending_change)await this.session.persist(stageChange(this.session.entries,entry.id,this.action.id,generatePassword(24)),generation);
    else if(entry.pending_change.action_id!==this.action.id)throw new Error('Another pending password change must be resolved first.');
    this.session.active(generation);await this.report(index,'needs_attention','site_confirmation_required');
    return this.item(index);
  }
  async open(index) {
    const generation=this.session.generation;const {approved}=await this.stage(index);this.session.active(generation);
    // The worker survives a popup closing when navigation focuses the website.
    const response=await this.browser.runtime.sendMessage({type:'open-account-change',origin:approved.origin});
    if(!response?.ok)throw new Error('Could not open the security page. The proposed password is safely staged; reopen the companion to continue.');
  }
  async prepare(index,tab) {
    const generation=this.session.generation,{approved,entry}=await this.stage(index);this.session.active(generation);
    if(!tab || validOrigin(new URL(tab.url).origin)!==approved.origin)throw new Error('Open the approved exact HTTPS website before preparing its form.');
    const result=await this.browser.tabs.sendMessage(tab.id,{type:'prepare-password-change',origin:approved.origin,current:entry.password,replacement:entry.pending_change.password,username:entry.username},{frameId:0});
    this.session.active(generation);
    const reason=result?.reason;
    if(!result?.ok) {
      const allowed=['unsupported_form','cross_origin','requires_signin'];
      await this.report(index,'needs_attention',allowed.includes(reason)?reason:'unsupported_form');
      throw new Error('A supported password-change form was not found on this exact origin. Sign in yourself or use the staged password in the site’s own change flow. Nothing was submitted.');
    }
    await this.report(index,'prepared','site_confirmation_required');
    return {prepared:true,submitted:false};
  }
  async finish(index,confirmed) {
    const generation=await this.fresh(),{entry}=this.item(index);
    if(entry.change_receipt?.action_id!==this.action.id)await this.session.persist(finishChange(this.session.entries,entry.id,this.action.id,confirmed),generation);
    else if(!confirmed)throw new Error('This replacement was already confirmed. It cannot be discarded as unused.');
    this.session.active(generation);return this.report(index,confirmed?'confirmed_by_user':'discarded');
  }
}
