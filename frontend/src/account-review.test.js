import {beforeEach,expect,it,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {applyReview,reviewCandidates} from './account-review';
import {recordHistory,trackChanges,isArchived} from './entry-history';
import {validateEntries,encryptVault,decryptWithKey} from './vault-crypto';
import {accountHealth} from './account-health';
import {stageChange} from './credential-changes';
const entry={id:'fixture-entry',type:'login',title:'Fixture account',origin:'https://example.test',username:'fixture',password:'fixture-only-secret'};
const old='2025-01-01T12:00:00.000Z',now='2026-10-19T12:00:00.000Z';
beforeEach(()=>vi.stubGlobal('crypto',webcrypto));

it('keeps unknown review history distinct from due dates, future dates and duplicate sites',()=>{
  const values=[entry,{...entry,id:'same-login',password:'different-secret'},{...entry,id:'different-user',username:'other'},recordHistory({...entry,id:'old-review'},'reviewed',old,{reviewed_at:old}),recordHistory({...entry,id:'future-review'},'reviewed','2027-01-01T00:00:00.000Z',{reviewed_at:'2027-01-01T00:00:00.000Z'})];
  const result=reviewCandidates(values,180,Date.parse(now));
  expect(result.find(e=>e.id===entry.id)).toMatchObject({history_unknown:true,review_due:false,duplicate:true});
  expect(result.find(e=>e.id==='old-review')).toMatchObject({history_unknown:false,review_due:true});
  expect(result.find(e=>e.id==='different-user').duplicate).toBe(false);
  expect(result.find(e=>e.id==='future-review')).toMatchObject({review_due:false,future_observation:true});
});
it('archives and restores exact selections without deleting credentials or confusing archival with website changes',()=>{
  const entries=[entry,{...entry,id:'other'}];
  const archived=applyReview(entries,[entry.id],'archive',now);
  expect(archived).toHaveLength(2);expect(archived[0].password).toBe(entry.password);expect(archived[1]).toEqual(entries[1]);
  expect(isArchived(archived[0])).toBe(true);
  const check=vi.fn(()=>({score:4}));expect(accountHealth(archived,check)).toHaveLength(1);expect(check).toHaveBeenCalledTimes(1);
  expect(()=>stageChange(archived,entry.id,'a'.repeat(24),'proposed')).toThrow('archived');
  const restored=applyReview(archived,[entry.id],'restore',now);
  expect(isArchived(restored[0])).toBe(false);expect(restored[0].history.events.map(e=>e.kind)).toEqual(['archived','restored']);
});
it('rejects missing, mixed-state and duplicate selections atomically and protects pending replacement recovery',()=>{
  expect(()=>applyReview([entry],['missing'],'archive',now)).toThrow('unavailable');
  expect(()=>applyReview([entry],[entry.id,entry.id],'archive',now)).toThrow('distinct');
  const pending=stageChange([entry],entry.id,'a'.repeat(24),'proposed');
  expect(()=>applyReview(pending,[entry.id],'archive',now)).toThrow('staged');
  const archived=applyReview([entry],[entry.id],'archive',now);
  expect(()=>applyReview([...archived,{...entry,id:'active'}],[entry.id,'active'],'restore',now)).toThrow('state changed');
  expect(pending[0].pending_change.password).toBe('proposed');
});
it('records bounded metadata without old secrets, preserves it across older-client updates, and leaves legacy history unknown',()=>{
  expect(trackChanges([entry],[{...entry}],now)[0].history).toBeUndefined();
  let next=trackChanges([],[entry],old);
  for(let i=0;i<12;i++)next=applyReview(next,[entry.id],'review',now);
  expect(next[0].history.events).toHaveLength(8);
  const updated=trackChanges(next,[{...entry,password:'new-fixture-secret'}],now)[0];
  expect(updated.history.saved_at).toBe(old);expect(updated.history.reviewed_at).toBe(now);
  expect(updated.history.events.at(-1).kind).toBe('credential_saved');
  expect(JSON.stringify(updated.history)).not.toContain(entry.password);expect(JSON.stringify(updated.history)).not.toContain('new-fixture-secret');
  expect(JSON.stringify(updated.history)).not.toContain(entry.username);
});
it('rejects injected history properties, excess events and invalid timestamps before encryption',()=>{
  for(const history of [{version:1,events:[],password:'should-not-be-here'},{version:1,events:Array(9).fill({kind:'saved',at:now})},{version:1,events:[{kind:'remote_verified',at:now}]},{version:1,events:[],reviewed_at:'2026-02-30T12:00:00.000Z'}])expect(()=>validateEntries([{...entry,history}])).toThrow('history');
});
it('keeps account review and archive history inside the encrypted personal payload',async()=>{
  const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),salt=crypto.getRandomValues(new Uint8Array(16));
  const reviewed=applyReview(trackChanges([],[entry],old),[entry.id],'review',now),archived=applyReview(reviewed,[entry.id],'archive',now);
  const envelope=await encryptVault(archived,key,salt);
  for(const value of [entry.password,entry.origin,entry.username,'archived_at','reviewed_at',now])expect(JSON.stringify(envelope)).not.toContain(value);
  expect(await decryptWithKey(envelope,key,salt)).toEqual(archived);
});
