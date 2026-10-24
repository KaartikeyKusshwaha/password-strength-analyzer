import {validateEntries} from './vault-crypto';
import {isArchived} from './entry-history';
export function stageChange(entries,entryId,actionId,password) {
  const entry=entries.find(e=>e.id===entryId && e.type==='login' && !isArchived(e));if(!entry)throw new Error('The approved login no longer exists or is archived.');
  if(entry.pending_change && entry.pending_change.action_id!==actionId)throw new Error('This login has another pending change. Finish or discard that proposal first.');
  if(entry.pending_change)return entries;
  const next=entries.map(e=>e.id===entryId?{...e,pending_change:{action_id:actionId,password,created_at:new Date().toISOString()}}:e);
  return validateEntries(next);
}
export function finishChange(entries,entryId,actionId,confirmed) {
  const entry=entries.find(e=>e.id===entryId && e.type==='login');if(!entry?.pending_change || entry.pending_change.action_id!==actionId)throw new Error('The staged password is unavailable. Reload the vault before continuing.');
  return validateEntries(entries.map(e=>{
    if(e.id!==entryId)return e;
    const {pending_change,...original}=e;
    return confirmed?{...original,password:pending_change.password,change_receipt:{action_id:actionId,confirmed_at:new Date().toISOString()}}:original;
  }));
}
export function withoutChangeState(entry) {const {pending_change,change_receipt,...value}=entry;return value;}
