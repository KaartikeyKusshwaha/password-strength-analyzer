import {beforeEach,expect,it,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {sealAction,openAction,validateAction} from './action-crypto';
import {stageChange,finishChange,withoutChangeState} from './credential-changes';
import {validateEntries} from './vault-crypto';
beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
const entry={id:'fixture-login',type:'login',title:'Fixture',origin:'https://example.test',username:'fixture',password:'old-fixture-password'};
function manifest() {const approved_at=Math.floor(Date.now()/1000);return {version:1,id:'a'.repeat(24),vault_id:'b'.repeat(24),actor:'c'.repeat(24),kind:'personal',approved_at,expires_at:approved_at+1800,items:[{entry_id:entry.id,origin:entry.origin}]};}
it('encrypts approvals with scope binding and rejects tampering, expiry and plaintext extras',async()=>{
  const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),value=manifest(),envelope=await sealAction(value,key),job={...value,user:value.actor,entry_count:1};
  expect(JSON.stringify(envelope)).not.toContain(entry.origin);expect(await openAction(envelope,key,job)).toEqual(value);
  for(const change of [{id:'e'.repeat(24)},{vault_id:'e'.repeat(24)},{actor:'e'.repeat(24)},{kind:'shared'},{entry_count:2}])await expect(openAction(envelope,key,{...job,...change})).rejects.toThrow();
  expect(()=>validateAction({...value,password:'not-allowed'})).toThrow();expect(()=>validateAction({...value,expires_at:value.approved_at-1})).toThrow();
  expect(()=>validateAction({...value,items:[{entry_id:entry.id,origin:'http://example.test'}]})).toThrow();
});
it('stages a recoverable password alongside the old login and promotes it only on confirmation',()=>{
  const id='a'.repeat(24),staged=stageChange([entry],entry.id,id,'new-fixture-password');
  expect(staged[0].password).toBe(entry.password);expect(staged[0].pending_change.password).toBe('new-fixture-password');
  expect(stageChange(staged,entry.id,id,'different-password')).toBe(staged);
  expect(()=>stageChange(staged,entry.id,'b'.repeat(24),'other')).toThrow('another pending');
  expect(finishChange(staged,entry.id,id,false)).toEqual([entry]);
  const confirmed=finishChange(staged,entry.id,id,true);expect(confirmed[0].password).toBe('new-fixture-password');expect(confirmed[0].pending_change).toBeUndefined();expect(confirmed[0].change_receipt.action_id).toBe(id);
  expect(withoutChangeState(staged[0])).toEqual(entry);
  expect(()=>validateEntries([{...entry,pending_change:{action_id:id,password:'new',created_at:'yesterday'}}])).toThrow();
});
