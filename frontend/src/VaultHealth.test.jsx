import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen,waitFor} from '@testing-library/react';
import {webcrypto} from 'node:crypto';
import VaultHealth from '../../companion/extension/VaultHealth';
import {SaveSession} from '../../companion/extension/vault-session';
import {scheduleKey,enableSchedule,loadSchedule,BREACH_INTERVAL} from '../../companion/extension/breach-schedule';
afterEach(()=>{cleanup();vi.unstubAllGlobals();});
function fixture(){
  vi.stubGlobal('crypto',webcrypto);
  const entries=[{id:'a',type:'login',title:'Site A',origin:'https://a.example.test',username:'private-user-a',password:'password'},{id:'b',type:'login',title:'Site B',origin:'https://b.example.test',username:'private-user-b',password:'password'}];
  const session=new SaveSession({});session.entries=entries;session.material={kind:'personal'};session.refresh=vi.fn(async()=>{});session.permitted=vi.fn();
  const browser={permissions:{request:vi.fn(async()=>true)},runtime:{sendMessage:vi.fn(async()=>({ok:true}))}};
  return {entries,session,browser,checkPassword:vi.fn(()=>({score:1}))};
}
function start(){fireEvent.click(screen.getByLabelText(/Allow hash-prefix lookups/));fireEvent.click(screen.getByRole('button',{name:'Check saved passwords for known exposure'}));}
it('automatically estimates locally, deduplicates opted-in lookups and never transmits entry metadata',async()=>{
  const props=fixture(),fetcher=vi.fn(async()=>({ok:true,text:async()=> '1E4C9B93F3F0682250B6CF8331B7EE68FD8:42'}));vi.stubGlobal('fetch',fetcher);
  render(<VaultHealth {...props}/>);expect(await screen.findByText('2 saved logins need review')).toBeInTheDocument();
  expect(fetcher).not.toHaveBeenCalled();expect(props.browser.permissions.request).not.toHaveBeenCalled();start();
  await waitFor(()=>expect(screen.getAllByText(/This password appears in the breach dataset/)).toHaveLength(2));
  expect(fetcher).toHaveBeenCalledTimes(1);expect(fetcher.mock.calls[0][0]).toBe('https://api.pwnedpasswords.com/range/5BAA6');
  const serialized=JSON.stringify(fetcher.mock.calls.map(([url,options])=>[new URL(url).pathname,options]));for(const secret of ['password','private-user-a','private-user-b','a.example.test','b.example.test','1E4C9B93'])expect(serialized).not.toContain(secret);
  expect(props.browser.permissions.request).toHaveBeenCalledWith({origins:['https://api.pwnedpasswords.com/*']});
});
it('sends no lookup after denial and leaves unavailable responses unassessed',async()=>{
  const props=fixture(),fetcher=vi.fn(async()=>({ok:false}));vi.stubGlobal('fetch',fetcher);props.browser.permissions.request.mockResolvedValueOnce(false);
  render(<VaultHealth {...props}/>);start();expect(await screen.findByRole('alert')).toHaveTextContent('declined');expect(fetcher).not.toHaveBeenCalled();
  start();await waitFor(()=>expect(screen.getAllByText(/breach lookup unassessed/)).toHaveLength(2));
  expect(screen.queryByText(/not found in password dataset/)).not.toBeInTheDocument();
});
it('aborts a pending lookup on vault lock and does not publish its result',async()=>{
  const props=fixture();let signal;
  const fetcher=vi.fn((url,options)=>new Promise((resolve,reject)=>{signal=options.signal;signal.addEventListener('abort',()=>reject(new DOMException('Stopped','AbortError')),{once:true});}));vi.stubGlobal('fetch',fetcher);
  render(<VaultHealth {...props}/>);start();await waitFor(()=>expect(fetcher).toHaveBeenCalledTimes(1));props.session.lock();
  await waitFor(()=>expect(signal.aborted).toBe(true));
  expect(screen.queryByText(/found in password dataset/)).not.toBeInTheDocument();
});
it('opens a reviewed password-change page after policy checks without sending the saved password',async()=>{
  const props=fixture();render(<VaultHealth {...props}/>);await screen.findByText('2 saved logins need review');
  fireEvent.click(screen.getAllByRole('button',{name:'Open password-change page'})[0]);
  await waitFor(()=>expect(props.browser.runtime.sendMessage).toHaveBeenCalledWith({type:'open-account-change',origin:'https://a.example.test'}));
  expect(props.session.permitted).toHaveBeenCalledWith('save','https://a.example.test');
  expect(JSON.stringify(props.browser.runtime.sendMessage.mock.calls)).not.toContain('password');
});
it('bounds a run to twenty logins and leaves the remaining scope for another approval',async()=>{
  const props=fixture();props.entries=Array.from({length:21},(_,index)=>({...props.entries[0],id:'entry'+index,title:'Login '+index}));props.session.entries=props.entries;
  const fetcher=vi.fn(async()=>({ok:true,text:async()=> '0'.repeat(35)+':0'}));vi.stubGlobal('fetch',fetcher);
  render(<VaultHealth {...props}/>);start();
  await screen.findByLabelText('Allow hash-prefix lookups for the next 1 saved logins in this vault.');
  expect(props.session.refresh).toHaveBeenCalledTimes(20);expect(fetcher).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('button',{name:'Check saved passwords for known exposure'})).toBeDisabled();
});
it('does not query passwords excluded by the vault browser policy',async()=>{
  const props=fixture(),fetcher=vi.fn();vi.stubGlobal('fetch',fetcher);props.session.permitted.mockImplementation(()=>{throw new Error('Restricted scope');});
  render(<VaultHealth {...props}/>);await screen.findByText('2 saved logins need review');
  fireEvent.click(screen.getByLabelText(/Allow hash-prefix lookups/));expect(screen.getByRole('button',{name:'Check saved passwords for known exposure'})).toBeDisabled();
  expect(props.browser.permissions.request).not.toHaveBeenCalled();expect(fetcher).not.toHaveBeenCalled();
});
it('creates an action approval only for explicitly selected logins',async()=>{
  const props=fixture();props.session.approveChanges=vi.fn(async()=>({status:'queued'}));const onApproved=vi.fn();
  render(<VaultHealth {...props} onApproved={onApproved}/>);await screen.findByText('2 saved logins need review');
  fireEvent.click(screen.getByLabelText('Site A'));
  fireEvent.click(screen.getByRole('button',{name:'Approve password changes for 1 selected logins'}));
  await waitFor(()=>expect(onApproved).toHaveBeenCalled());expect(props.session.approveChanges).toHaveBeenCalledWith(['a']);
  expect(props.browser.runtime.sendMessage).not.toHaveBeenCalled();
});

function recurringFixture(){
  const props=fixture(),saved={},listeners=new Set();
  props.session.config={origin:'https://security.example.test'};
  props.session.policy={id:'a'.repeat(24),origins:[],browser_enabled:true,browser_fill:true,browser_save:true};
  props.browser.permissions.contains=vi.fn(async()=>true);
  props.browser.storage={local:{get:vi.fn(async()=>structuredClone(saved)),set:vi.fn(async value=>{Object.assign(saved,structuredClone(value));}),remove:vi.fn(async keys=>{for(const key of Array.isArray(keys)?keys:[keys])delete saved[key];})},onChanged:{addListener:fn=>listeners.add(fn),removeListener:fn=>listeners.delete(fn)}};
  return {props,saved,listeners,key:scheduleKey(props.session)};
}
it('waits for opt-in and a later unlock, then rechecks daily without another permission prompt',async()=>{
  const {props,key}=recurringFixture(),fetcher=vi.fn(async()=>({ok:true,text:async()=> '0'.repeat(35)+':0'}));vi.stubGlobal('fetch',fetcher);
  const first=render(<VaultHealth {...props}/>);
  const enable=await screen.findByRole('button',{name:'Allow daily checks on unlock for this vault'});
  expect(fetcher).not.toHaveBeenCalled();fireEvent.click(enable);
  await screen.findByRole('button',{name:'Disable recurring password checks'});expect(fetcher).not.toHaveBeenCalled();first.unmount();
  const second=render(<VaultHealth {...props}/>);
  await waitFor(()=>expect(fetcher).toHaveBeenCalledTimes(1));
  await waitFor(async()=>expect((await loadSchedule(props.browser,key)).checkedAt).toBeGreaterThan(0));
  expect(props.browser.permissions.request).toHaveBeenCalledTimes(1);expect(props.browser.permissions.contains).toHaveBeenCalled();second.unmount();
  render(<VaultHealth {...props}/>);await screen.findByRole('button',{name:'Disable recurring password checks'});
  expect(fetcher).toHaveBeenCalledTimes(1);expect((await loadSchedule(props.browser,key)).checkedAt+BREACH_INTERVAL).toBeGreaterThan(Date.now());
});
it('aborts a recurring lookup when consent is disabled from another window',async()=>{
  const {props,key,saved,listeners}=recurringFixture();await enableSchedule(props.browser,key);let signal;
  const fetcher=vi.fn((url,options)=>new Promise((resolve,reject)=>{signal=options.signal;signal.addEventListener('abort',()=>reject(new DOMException('Stopped','AbortError')),{once:true});}));vi.stubGlobal('fetch',fetcher);
  render(<VaultHealth {...props}/>);await waitFor(()=>expect(fetcher).toHaveBeenCalledTimes(1));
  const oldValue=saved[key];delete saved[key];for(const callback of listeners)callback({[key]:{oldValue}},'local');
  await waitFor(()=>expect(signal.aborted).toBe(true));
  await screen.findByRole('button',{name:'Allow daily checks on unlock for this vault'});
  expect((await loadSchedule(props.browser,key)).enabled).toBe(false);
  expect(screen.queryByText(/not found in password dataset/)).not.toBeInTheDocument();
});

it('does not advance successful-check time or cursor after a recurring provider failure',async()=>{
  const {props,key}=recurringFixture();await enableSchedule(props.browser,key);
  const fetcher=vi.fn(async()=>({ok:false}));vi.stubGlobal('fetch',fetcher);
  render(<VaultHealth {...props}/>);await waitFor(()=>expect(fetcher).toHaveBeenCalled());
  await waitFor(async()=>expect((await loadSchedule(props.browser,key)).retryAt).toBeGreaterThan(Date.now()));
  const after=await loadSchedule(props.browser,key);expect(after.checkedAt).toBe(0);expect(after.offset).toBe(0);
  expect(props.browser.permissions.request).not.toHaveBeenCalled();
  expect(screen.queryByText(/not found in password dataset/)).not.toBeInTheDocument();
});
