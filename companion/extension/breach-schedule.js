import {serviceOrigin} from './policy';
export const BREACH_INTERVAL=24*60*60*1000;
export function scheduleKey(session){
  const id=session.policy?.id,kind=session.material?.kind;
  if(!/^[a-f0-9]{24}$/.test(id)||!['personal','shared'].includes(kind))throw new Error('A verified unlocked vault is required.');
  return 'breachSchedule:'+encodeURIComponent(serviceOrigin(session.config?.origin))+':'+kind+':'+id;
}
export function normalizeSchedule(value,now=Date.now()){
  if(value?.enabled!==true)return {enabled:false,checkedAt:0,retryAt:0,offset:0};
  return {enabled:true,generation:value.generation,checkedAt:Number.isFinite(value.checkedAt)&&value.checkedAt>=0&&value.checkedAt<=now?value.checkedAt:0,retryAt:Number.isFinite(value.retryAt)&&value.retryAt>=0&&value.retryAt<=now+BREACH_INTERVAL?value.retryAt:0,offset:Number.isSafeInteger(value.offset)&&value.offset>=0&&value.offset<=100000?value.offset:0};
}
export function scheduleDue(value,now=Date.now()){
  const schedule=normalizeSchedule(value,now);
  return schedule.enabled&&now>=schedule.retryAt&&(!schedule.checkedAt||now-schedule.checkedAt>=BREACH_INTERVAL);
}
export function scheduleBatch(entries,schedule){
  if(!entries.length)return [];
  const start=normalizeSchedule(schedule).offset%entries.length;
  return Array.from({length:Math.min(20,entries.length)},(_,index)=>entries[(start+index)%entries.length]);
}
export async function loadSchedule(browser,key){
  const saved=await browser.storage.local.get([key,key+':progress']),consent=saved[key],progress=saved[key+':progress'];
  if(consent?.enabled!==true||!/^[a-f0-9]{32}$/.test(consent.generation))return normalizeSchedule(null);
  return normalizeSchedule({enabled:true,generation:consent.generation,...(progress?.generation===consent.generation?{checkedAt:progress.checkedAt,retryAt:progress.retryAt,offset:progress.offset}:{})});
}
export async function enableSchedule(browser,key){
  const generation=crypto.randomUUID().replaceAll('-','');
  await browser.storage.local.set({[key]:{enabled:true,generation}});
  return normalizeSchedule({enabled:true,generation});
}
export async function disableSchedule(browser,key){
  await browser.storage.local.remove([key,key+':progress']);return normalizeSchedule(null);
}
export async function advanceSchedule(browser,key,value){
  const current=await loadSchedule(browser,key);
  if(!current.enabled||current.generation!==value.generation)return current;
  const safe=normalizeSchedule(value);
  // Progress never writes the consent key. A concurrent stop cannot be undone
  // by a stale completion, even across multiple popup windows.
  await browser.storage.local.set({[key+':progress']:{generation:value.generation,checkedAt:safe.checkedAt,retryAt:safe.retryAt,offset:safe.offset}});
  return loadSchedule(browser,key);
}
