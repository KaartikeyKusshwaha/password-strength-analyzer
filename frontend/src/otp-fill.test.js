import {beforeEach,afterEach,expect,it,vi} from 'vitest';
import {fillOtp,inspectOtp} from '../../companion/extension/otp-form';
import {fillSavedCode} from '../../companion/extension/autofill-client';
import {SaveSession} from '../../companion/extension/vault-session';
import {validateEntries} from './vault-crypto';
beforeEach(()=>{document.body.innerHTML='<form action="https://accounts.example.test/verify"><input autocomplete="one-time-code" name="otp"></form>';vi.spyOn(HTMLElement.prototype,'getClientRects').mockReturnValue([{width:50,height:20}]);});
afterEach(()=>vi.restoreAllMocks());
const origin='https://accounts.example.test';
it('fills one explicit verification field on the exact origin without submission',()=>{
  const submit=vi.fn();document.querySelector('form').addEventListener('submit',submit);
  expect(inspectOtp(document,origin+'/verify',origin)).toEqual({ok:true});
  expect(fillOtp(document,origin+'/verify',{origin,code:'123456'})).toEqual({ok:true});
  expect(document.querySelector('input').value).toBe('123456');expect(submit).not.toHaveBeenCalled();
});
it('rejects mismatched origins, cross-origin form actions and multiple code fields',()=>{
  expect(fillOtp(document,origin+'/verify',{origin:'https://lookalike.example.test',code:'123456'}).ok).toBe(false);
  document.querySelector('form').action='https://other.example/collect';
  expect(fillOtp(document,origin+'/verify',{origin,code:'123456'}).ok).toBe(false);
  document.querySelector('form').action=origin+'/verify';document.querySelector('form').append(document.querySelector('input').cloneNode());
  expect(fillOtp(document,origin+'/verify',{origin,code:'123456'}).ok).toBe(false);
  expect(document.querySelector('input').value).toBe('');
});
it('does not generate a code before receiver inspection and does not transmit after navigation',async()=>{
  const session={generation:1,active:vi.fn(),codeFor:vi.fn(async()=>'123456')};
  const browser={tabs:{sendMessage:vi.fn(async()=>({ok:false,version:'test'})),query:vi.fn(async()=>[{id:1,url:'https://other.example/'}])}};
  await expect(fillSavedCode(browser,session,'id',{id:1,origin},'test')).rejects.toThrow('No current');
  expect(session.codeFor).not.toHaveBeenCalled();
  browser.tabs.sendMessage.mockResolvedValue({ok:true,version:'test'});
  await expect(fillSavedCode(browser,session,'id',{id:1,origin},'test')).rejects.toThrow('Website changed');
  expect(browser.tabs.sendMessage.mock.calls.every(([,m])=>!('code' in m))).toBe(true);
});
it('requires explicit encrypted origin binding and enforces vault origin policy',async()=>{
  const entry={id:'totp-test',type:'totp',title:'Account',secret:'JBSWY3DPEHPK3PXP',digits:6,period:30,algorithm:'SHA-1'};
  validateEntries([entry]);
  expect(()=>validateEntries([{...entry,autofill_origin:origin+'/path'}])).toThrow('exact HTTPS');
  const session=new SaveSession({});session.entries=[entry];session.refresh=vi.fn(async()=>{});
  await expect(session.codeFor(entry.id,origin)).rejects.toThrow('Link this authenticator');
  session.policy={browser_enabled:true,browser_save:true,browser_fill:true,origins:['https://other.example']};
  await expect(session.bindCode(entry.id,origin)).rejects.toThrow('does not permit');
  session.policy=null;session.persist=vi.fn(async()=>{});
  await session.bindCode(entry.id,origin);
  expect(session.persist.mock.calls[0][0][0].autofill_origin).toBe(origin);
});
