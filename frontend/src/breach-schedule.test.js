import {afterEach,expect,it,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {advanceSchedule,enableSchedule,disableSchedule,loadSchedule,scheduleBatch,scheduleDue,scheduleKey,BREACH_INTERVAL} from '../../companion/extension/breach-schedule';
afterEach(()=>vi.unstubAllGlobals());
function fixture(){
  vi.stubGlobal('crypto',webcrypto);const saved={};
  const browser={storage:{local:{get:vi.fn(async()=>structuredClone(saved)),set:vi.fn(async data=>Object.assign(saved,structuredClone(data))),remove:vi.fn(async keys=>{for(const key of Array.isArray(keys)?keys:[keys])delete saved[key];})}}};
  return {browser,saved};
}
it('scopes consent to the exact app, kind and vault, and rejects unverified vaults',()=>{
  const session={config:{origin:'https://security.example.test'},policy:{id:'a'.repeat(24)},material:{kind:'personal'}};
  const key=scheduleKey(session);expect(scheduleKey({...session,material:{kind:'shared'}})).not.toBe(key);
  expect(scheduleKey({...session,policy:{id:'b'.repeat(24)}})).not.toBe(key);
  expect(()=>scheduleKey({...session,material:null})).toThrow();expect(()=>scheduleKey({...session,config:{origin:'http://evil.example.test'}})).toThrow();
});
it('is off by default, checks daily only when due and rotates bounded batches',async()=>{
  const {browser,saved}=fixture(),key='fixture';expect(scheduleDue(await loadSchedule(browser,key))).toBe(false);
  const schedule=await enableSchedule(browser,key);expect(scheduleDue(schedule)).toBe(true);
  const entries=Array.from({length:25},(_,id)=>({id}));
  expect(scheduleBatch(entries,schedule).map(entry=>entry.id)).toEqual(Array.from({length:20},(_,i)=>i));
  const now=Date.now();const done=await advanceSchedule(browser,key,{...schedule,checkedAt:now,offset:20});
  expect(scheduleDue(done,now+BREACH_INTERVAL-1)).toBe(false);expect(scheduleDue(done,now+BREACH_INTERVAL)).toBe(true);
  expect(scheduleBatch(entries,done).map(entry=>entry.id)).toEqual([20,21,22,23,24,...Array.from({length:15},(_,i)=>i)]);
  expect(Object.values(saved).every(value=>Object.keys(value).every(name=>['enabled','generation','checkedAt','retryAt','offset'].includes(name)))).toBe(true);
});
it('cannot resurrect consent when disabling races with completion',async()=>{
  const {browser,saved}=fixture(),key='fixture',schedule=await enableSchedule(browser,key);
  const original=browser.storage.local.set.getMockImplementation();
  browser.storage.local.set.mockImplementationOnce(async value=>{await disableSchedule(browser,key);return original(value);});
  const after=await advanceSchedule(browser,key,{...schedule,checkedAt:Date.now(),offset:20});
  expect(after.enabled).toBe(false);expect(saved[key]).toBeUndefined();
  expect((await loadSchedule(browser,key)).enabled).toBe(false);
});
it('rejects stale progress after re-consent and preserves the next batch after retry',async()=>{
  const {browser}=fixture(),key='fixture',old=await enableSchedule(browser,key);
  await disableSchedule(browser,key);const next=await enableSchedule(browser,key);expect(next.generation).not.toBe(old.generation);
  expect((await advanceSchedule(browser,key,{...old,checkedAt:Date.now(),offset:20})).checkedAt).toBe(0);
  const retryAt=Date.now()+3600000;
  const failed=await advanceSchedule(browser,key,{...next,retryAt});
  expect(failed.checkedAt).toBe(0);expect(failed.offset).toBe(0);expect(scheduleDue(failed)).toBe(false);expect(scheduleDue(failed,retryAt)).toBe(true);
});
