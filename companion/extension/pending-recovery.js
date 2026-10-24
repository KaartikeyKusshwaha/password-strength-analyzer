import {finishChange,withoutChangeState} from '../../frontend/src/credential-changes';
import {isArchived,recordHistory} from '../../frontend/src/entry-history';
const terminal=new Set(['complete','cancelled','expired']);
const known=new Set([...terminal,'queued','running','awaiting_confirmation','interrupted']);

// Local vault maintenance, never a way to resume an expired website action.
export class PendingRecovery {
  constructor(session){this.session=session;}
  async inspect(){
    const generation=this.session.generation,jobs=await this.session.actions();this.session.active(generation);
    return this.session.entries.filter(entry=>entry.type==='login'&&entry.pending_change&&!isArchived(entry)).map(entry=>{
      const job=jobs.find(item=>item.id===entry.pending_change.action_id);
      return {id:entry.id,action:entry.pending_change.action_id,status:job?.status||'untracked',canRecover:!job||terminal.has(job.status),job:job?{id:job.id,status:job.status}:null};
    });
  }
  async fresh(identifier,action,permission){
    const generation=this.session.generation,jobs=await this.session.actions();this.session.active(generation);
    const entry=this.session.entries.find(item=>item.id===identifier&&item.type==='login'&&!isArchived(item));
    if(!entry?.pending_change||entry.pending_change.action_id!==action)throw new Error('The staged proposal changed. Refresh its recovery status.');
    this.session.permitted(permission,entry.origin);
    const job=jobs.find(item=>item.id===action);
    if(job&&!known.has(job.status))throw new Error('Unsupported account-plan status. Refresh before recovery.');
    return {entry,job,generation};
  }
  async reveal(identifier,action){
    const {entry,generation}=await this.fresh(identifier,action,'fill');
    this.session.active(generation);return {password:entry.pending_change.password,generation};
  }
  async resolve(identifier,action,confirmed){
    if(typeof confirmed!=='boolean')throw new Error('Choose an explicit website outcome.');
    const {entry,job,generation}=await this.fresh(identifier,action,'save');
    if(job&&!terminal.has(job.status))throw new Error('Stop the matching account plan before resolving its staged password.');
    if(this.session.entries.length>=200)throw new Error('Recovery needs room for an encrypted archived copy. Export or free an entry before continuing.');
    const at=new Date().toISOString(),{history,...base}=withoutChangeState(entry);
    const recovery=recordHistory({...base,id:crypto.randomUUID(),title:('Recovery copy · '+entry.title).slice(0,100),password:confirmed?entry.password:entry.pending_change.password},'archived',at,{archived_at:at,saved_at:at});
    const next=[...finishChange(this.session.entries,identifier,action,confirmed),recovery];
    this.session.active(generation);await this.session.persist(next,generation);this.session.active(generation);
    return {resolved:true,confirmed,recoveryId:recovery.id,queueChanged:false};
  }
}
