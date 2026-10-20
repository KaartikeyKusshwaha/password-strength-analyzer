import {validateEntries} from './vault-crypto';
import {isArchived,recordHistory,validTime} from './entry-history';

export function reviewCandidates(entries,days=180,clock=Date.now()){
  if(![90,180,365].includes(days) || !Number.isFinite(clock))throw new Error('Unsupported review interval.');
  const counts=new Map();
  for(const e of entries.filter(e=>e.type==='login' && !isArchived(e))){const key=JSON.stringify([e.origin,e.username]);counts.set(key,(counts.get(key)||0)+1);}
  return entries.map(entry=>{
    const reviewed=entry.history?.reviewed_at,age=reviewed?clock-Date.parse(reviewed):null;
    return {id:entry.id,archived:isArchived(entry),history_unknown:!reviewed,review_due:!isArchived(entry) && age!==null && age>=days*86400000,duplicate:!isArchived(entry) && entry.type==='login' && counts.get(JSON.stringify([entry.origin,entry.username]))>1,pending:!!entry.pending_change,future_observation:!!reviewed && age<0};
  });
}
export function applyReview(entries,ids,action,at=new Date().toISOString()){
  validateEntries(entries);
  if(!Array.isArray(ids)||!ids.length||ids.length>20||new Set(ids).size!==ids.length||!['review','archive','restore'].includes(action)||!validTime(at))throw new Error('Select 1–20 distinct accounts and a supported review action.');
  const selected=ids.map(id=>entries.find(e=>e.id===id));
  if(selected.some(e=>!e))throw new Error('A selected account changed or is unavailable. Review a fresh plan.');
  if(selected.some(e=>action==='restore'?!isArchived(e):isArchived(e)))throw new Error('Account archive state changed. Review a fresh plan.');
  if(action==='archive' && selected.some(e=>e.pending_change))throw new Error('Finish or discard staged password changes before archiving.');
  return validateEntries(entries.map(entry=>!ids.includes(entry.id)?entry:action==='review'?recordHistory(entry,'reviewed',at,{reviewed_at:at}):action==='archive'?recordHistory(entry,'archived',at,{archived_at:at}):recordHistory(entry,'restored',at,{archived_at:undefined})));
}
