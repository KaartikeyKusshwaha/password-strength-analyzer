import {expect,it,vi} from 'vitest';
import {fillSavedLogin} from '../../companion/extension/autofill-client';
const active={id:123,origin:'https://example.test'},version='0.12.5';
function fixture(check={ok:true,version}) {
  const entry={origin:active.origin,username:'public-fixture',password:'test-only'};
  return {entry,browser:{tabs:{sendMessage:vi.fn().mockResolvedValueOnce(check).mockResolvedValueOnce({ok:true})}},session:{generation:4,fill:vi.fn(async()=>entry),active:vi.fn()}};
}
it('checks a matching content version and main-frame target before accessing or transmitting a saved login',async()=>{
  const {browser,session,entry}=fixture();
  await fillSavedLogin(browser,session,'entry',active,version);
  expect(browser.tabs.sendMessage.mock.calls).toEqual([[123,{type:'inspect-login',origin:active.origin},{frameId:0}],[123,{type:'fill-login',entry},{frameId:0}]]);
  expect(browser.tabs.sendMessage.mock.invocationCallOrder[0]).toBeLessThan(session.fill.mock.invocationCallOrder[0]);
  expect(session.active).toHaveBeenCalledWith(4);
});
it.each([undefined,{ok:true,version:'0.12.4'},{ok:false,version,reason:'password_field'},{ok:false,version,reason:'origin'}])('does not access credentials when the preflight fails: %s',async check=>{
  const {browser,session}=fixture(check);browser.tabs.sendMessage.mockReset().mockResolvedValue(check);
  await expect(fillSavedLogin(browser,session,'entry',active,version)).rejects.toThrow();
  expect(session.fill).not.toHaveBeenCalled();expect(browser.tabs.sendMessage).toHaveBeenCalledTimes(1);
});
it('describes a missing receiver without leaking the native error',async()=>{
  const {browser,session}=fixture();browser.tabs.sendMessage.mockReset().mockRejectedValue(new Error('sensitive browser internals'));
  await expect(fillSavedLogin(browser,session,'entry',active,version)).rejects.toThrow('The website companion is unavailable.');
  expect(session.fill).not.toHaveBeenCalled();
});
it('does not send credentials if the vault locks while fetching a fill entry',async()=>{
  const {browser,session}=fixture();session.active.mockImplementation(()=>{throw new Error('Vault locked');});
  await expect(fillSavedLogin(browser,session,'entry',active,version)).rejects.toThrow('Vault locked');
  expect(browser.tabs.sendMessage).toHaveBeenCalledTimes(1);
});
it('reports the target refusal rather than claiming successful filling',async()=>{
  const {browser,session}=fixture();browser.tabs.sendMessage.mockReset().mockResolvedValueOnce({ok:true,version}).mockResolvedValueOnce({ok:false,reason:'form_action'});
  await expect(fillSavedLogin(browser,session,'entry',active,version)).rejects.toThrow('This form sends to another origin.');
});
