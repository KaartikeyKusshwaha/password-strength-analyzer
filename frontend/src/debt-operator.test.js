import {expect,it,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {approveDebtRotation,debtReference,registerSharedLogins,recoverDebtBinding,retireSharedLogin,restoreDebtLogin} from '../../companion/extension/debt-operator';
const connection={origin:'https://example.test',kind:'access',token:'a'.repeat(54)};
function session(){const saved={};return {saved,browser:{storage:{local:{get:vi.fn(async()=>({...saved})),set:vi.fn(async value=>Object.assign(saved,value)),remove:vi.fn(async key=>{delete saved[key];})}}},material:{kind:'shared'},policy:{id:'vault'},config:{origin:connection.origin},entries:[{id:'entry',type:'login',title:'Agency account',origin:'https://github.com',password:'never-send-this-fixture'}],external:vi.fn(async work=>work({active:()=>{}})),approveChanges:vi.fn(async()=>({id:'f'.repeat(24)}))};}
it('registers only explicit metadata and a vault-bound opaque reference',async()=>{
  vi.stubGlobal('crypto',webcrypto);const value=session(),request=vi.fn(async()=>({id:'record'}));
  Object.defineProperty(value.entries[0],'password',{get:()=>{throw new Error('Metadata must not read a password');}});
  await registerSharedLogins(value,connection,'client',['entry'],'github',request);
  expect(request.mock.calls[0][2]).toEqual({client_id:'client',vault_id:'vault',domain:'github.com',account_label:'Agency account',platform:'github',entry_ref:await debtReference('vault','entry')});
  expect(await debtReference('another-vault','entry')).not.toBe(await debtReference('vault','entry'));
});
it('persists a metadata-only link intent and retries without approving a second encrypted plan',async()=>{
  vi.stubGlobal('crypto',webcrypto);const value=session(),request=vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValue({ok:true});
  const row={id:'r',vault:'vault',entry_ref:await debtReference('vault','entry'),state:'needed'};
  await expect(approveDebtRotation(value,connection,[row],request)).rejects.toThrow('offline');
  expect(value.saved.debtPendingBinding.body).toEqual({action_id:'f'.repeat(24),items:[{exposure_id:'r',index:0}]});
  expect(JSON.stringify(value.saved)).not.toContain('never-send');
  await recoverDebtBinding(value,connection,request);
  expect(value.approveChanges).toHaveBeenCalledTimes(1);expect(value.saved.debtPendingBinding).toBeUndefined();
});
it('does not approve unknown records or use an unlocked vault from another service',async()=>{
  vi.stubGlobal('crypto',webcrypto);const value=session(),request=vi.fn();
  await expect(approveDebtRotation(value,connection,[{id:'r',vault:'vault',entry_ref:'unknown',state:'needed'}],request)).rejects.toThrow('do not match');
  expect(value.approveChanges).not.toHaveBeenCalled();
  await expect(registerSharedLogins(value,{...connection,origin:'https://other.test'},'client',['entry'],'github',request)).rejects.toThrow('shared vault on this service');
});

it('archives locally before retirement and retries failed metadata confirmation without re-encrypting twice',async()=>{
  vi.stubGlobal('crypto',webcrypto);const value=session(),request=vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValue({ok:true}),changed=vi.fn();
  value.refresh=vi.fn(async()=>{});value.persist=vi.fn(async entries=>{value.entries=entries;});value.entries[0].change_receipt={action_id:'job'};
  const row={id:'r',vault:'vault',entry_ref:await debtReference('vault','entry'),state:'verified',action_id:'job'};
  await expect(retireSharedLogin(value,connection,row,request,changed)).rejects.toThrow('archived locally');
  expect(value.entries[0].history.archived_at).toBeTruthy();expect(changed).toHaveBeenCalledTimes(1);
  await retireSharedLogin(value,connection,row,request,changed);expect(value.persist).toHaveBeenCalledTimes(1);
  expect(JSON.stringify(request.mock.calls)).not.toContain('never-send-this-fixture');
  await restoreDebtLogin(value,connection,{...row,state:'needed'},changed);
  expect(value.entries[0].history.archived_at).toBeUndefined();
});
it('does not retire debt if the local login has another pending change or rotation receipt',async()=>{
  vi.stubGlobal('crypto',webcrypto);const value=session(),request=vi.fn();value.refresh=vi.fn(async()=>{});value.persist=vi.fn();
  const row={id:'r',vault:'vault',entry_ref:await debtReference('vault','entry'),state:'verified',action_id:'another-job'};
  await expect(retireSharedLogin(value,connection,row,request)).rejects.toThrow('rotation receipt changed');
  expect(value.persist).not.toHaveBeenCalled();expect(request).not.toHaveBeenCalled();
});
