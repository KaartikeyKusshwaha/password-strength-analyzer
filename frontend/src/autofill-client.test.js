import {expect,it,vi} from 'vitest';
import {fillSavedLogin} from '../../companion/extension/autofill-client';
const active={id:123,origin:'https://example.test'},version='0.12.6';
function fixture(check={ok:true,version}) {
  const entry={origin:active.origin,username:'public-fixture',password:'test-only'};
  return {entry,browser:{tabs:{sendMessage:vi.fn().mockResolvedValueOnce(check).mockResolvedValueOnce({ok:true,filled:'login'})}},session:{generation:4,fill:vi.fn(async()=>entry),active:vi.fn()}};
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
  await expect(fillSavedLogin(browser,session,'entry',active,version)).rejects.toThrow('The website companion did not answer.');
  expect(session.fill).not.toHaveBeenCalled();
});

it('reports each stage in order and bounds an unanswered preflight before accessing credentials',async()=>{
  const progress=vi.fn(),success=fixture();
  await fillSavedLogin(success.browser,success.session,'entry',active,version,progress);
  expect(progress.mock.calls.map(([text])=>text)).toEqual(['Checking this sign-in form…','Checking current vault access…','Filling the selected login; waiting for the website…']);
  vi.useFakeTimers();
  try {
    const {browser,session}=fixture();browser.tabs.sendMessage.mockReset().mockImplementation(()=>new Promise(()=>{}));
    const pending=expect(fillSavedLogin(browser,session,'entry',active,version)).rejects.toThrow('No saved credentials were sent');
    await vi.advanceTimersByTimeAsync(5000);await pending;
    expect(session.fill).not.toHaveBeenCalled();expect(browser.tabs.sendMessage).toHaveBeenCalledTimes(1);
  }finally{vi.useRealTimers();}
});

it('does not resend a credential message after a missing fill receipt or claim it never arrived',async()=>{
  vi.useFakeTimers();
  try {
    const {browser,session}=fixture();browser.tabs.sendMessage.mockReset().mockResolvedValueOnce({ok:true,version}).mockImplementation(()=>new Promise(()=>{}));
    const pending=expect(fillSavedLogin(browser,session,'entry',active,version)).rejects.toThrow('the message may have arrived');
    await vi.advanceTimersByTimeAsync(5000);await pending;
    expect(browser.tabs.sendMessage.mock.calls.filter(([,message])=>message.type==='fill-login')).toHaveLength(1);
  }finally{vi.useRealTimers();}
});
it('does not send credentials if the vault locks while fetching a fill entry',async()=>{
  const {browser,session,entry}=fixture();
  session.fill.mockImplementation(async()=>{session.generation++;return entry;});
  session.active.mockImplementation(mark=>{if(mark!==session.generation)throw new Error('Vault locked');});
  await expect(fillSavedLogin(browser,session,'entry',active,version)).rejects.toThrow('Vault locked');
  expect(session.fill).toHaveBeenCalledTimes(1);
  expect(browser.tabs.sendMessage).toHaveBeenCalledTimes(1);
});

it('does not access a newly unlocked session after the original preflight returns late',async()=>{
  const {browser,session}=fixture();let reply;
  browser.tabs.sendMessage.mockReset().mockImplementation(()=>new Promise(resolve=>{reply=resolve;}));
  session.active.mockImplementation(mark=>{if(mark!==session.generation)throw new Error('Vault locked');});
  const pending=expect(fillSavedLogin(browser,session,'entry',active,version)).rejects.toThrow('Vault locked');
  session.generation++;
  reply({ok:true,version});await pending;
  expect(session.fill).not.toHaveBeenCalled();expect(browser.tabs.sendMessage).toHaveBeenCalledTimes(1);
});
it('reports the target refusal rather than claiming successful filling',async()=>{
  const {browser,session}=fixture();browser.tabs.sendMessage.mockReset().mockResolvedValueOnce({ok:true,version}).mockResolvedValueOnce({ok:false,reason:'form_action'});
  await expect(fillSavedLogin(browser,session,'entry',active,version)).rejects.toThrow('This form sends to another origin.');
});
it.each(['form_changed','value_rejected'])('reports a website failure after filling without resending credentials: %s',async reason=>{
  const {browser,session}=fixture();browser.tabs.sendMessage.mockReset().mockResolvedValueOnce({ok:true,version}).mockResolvedValueOnce({ok:false,reason});
  await expect(fillSavedLogin(browser,session,'entry',active,version)).rejects.toThrow(/website/i);
  expect(browser.tabs.sendMessage.mock.calls.filter(([,message])=>message.type==='fill-login')).toHaveLength(1);
});
it('returns a password-only receipt and rejects an incomplete success acknowledgement',async()=>{
  const {browser,session}=fixture();browser.tabs.sendMessage.mockReset().mockResolvedValueOnce({ok:true,version}).mockResolvedValueOnce({ok:true,filled:'password'});
  await expect(fillSavedLogin(browser,session,'entry',active,version)).resolves.toBe('password');
  const incomplete=fixture();incomplete.browser.tabs.sendMessage.mockReset().mockResolvedValueOnce({ok:true,version}).mockResolvedValueOnce({ok:true});
  await expect(fillSavedLogin(incomplete.browser,incomplete.session,'entry',active,version)).rejects.toThrow('did not confirm');
});
