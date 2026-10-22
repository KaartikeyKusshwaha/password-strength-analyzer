import {beforeEach,expect,it,vi} from 'vitest';
import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import {webcrypto} from 'node:crypto';
import {Popup} from '../../companion/extension/popup';
import {Frame} from '../../companion/extension/vault-frame';
import native from './fixtures/native-sharing.json';
import manifest from '../../companion/extension/public/manifest.json';

let browser,fetcher,value;
beforeEach(()=>{
  vi.stubGlobal('crypto',webcrypto);
  const config={origin:'http://127.0.0.1:8110',token:'fixture-only-never-real',vaultId:native.team.id,vaultName:'Shared client',vaultKind:'shared',ownerIsSelf:true};
  browser={storage:{local:{get:vi.fn(async()=>({connection:config,connections:[config]})),set:vi.fn(),remove:vi.fn()}},runtime:{getManifest:()=>manifest,sendMessage:vi.fn(async()=>null)},tabs:{query:vi.fn(async()=>[{id:41,url:'https://example.test/login'}]),sendMessage:vi.fn(async(id,message)=>message.type==='inspect-login'?{ok:true,version:manifest.version}:{ok:true,filled:'login'})}};
  value={kind:'shared',revision:1,envelope:native.team.payload,vault:{id:native.team.id,name:'Shared client',kind:'shared',browser_save:false,browser_fill:true,origins:[],lock_seconds:30},sharing:{user_id:native.user,identity:native.identity,team:structuredClone(native.team)}};
  fetcher=vi.fn(async(url,options)=>({ok:true,status:200,json:async()=>options.method==='POST'?{revision:2}:value}));
  vi.stubGlobal('chrome',browser);vi.stubGlobal('fetch',fetcher);
});
it('the popup opens a shared vault locally and checks fresh policy before filling a selected login',async()=>{
  render(<Popup/>);await screen.findByLabelText('Sharing passphrase');
  fireEvent.change(screen.getByLabelText('Sharing passphrase'),{target:{value:native.password}});fireEvent.click(screen.getByRole('button',{name:'Unlock'}));
  // Real Argon2 + native key import may exceed RTL's default one-second wait under load.
  await screen.findByText('Unlocked · this popup only',{}, {timeout:10000});expect(screen.queryByText('Save a login manually')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'Fill this login'}));
  await waitFor(()=>expect(browser.tabs.sendMessage).toHaveBeenCalledWith(41,{type:'fill-login',entry:{origin:native.entry.origin,username:native.entry.username,password:native.entry.password}},{frameId:0}),{timeout:5000});
  await screen.findByText('Username and password filled. Review the website before submitting.');
  browser.tabs.sendMessage.mockClear();value={...value,vault:{...value.vault,browser_fill:false}};
  fireEvent.click(screen.getByRole('button',{name:'Fill this login'}));await screen.findByRole('alert');
  expect(browser.tabs.sendMessage).toHaveBeenCalledTimes(1);
  expect(browser.tabs.sendMessage).toHaveBeenCalledWith(41,{type:'inspect-login',origin:native.entry.origin},{frameId:0});
  expect(JSON.stringify(browser.tabs.sendMessage.mock.calls)).not.toContain(native.entry.password);
  expect(JSON.stringify(fetcher.mock.calls)).not.toContain(native.password);
},15000);
it('the in-page panel confirms replacement and sends only encrypted shared data',async()=>{
  value={...value,vault:{...value.vault,browser_save:true}};
  browser.runtime.sendMessage.mockImplementation(async message=>message.type==='frame-capture'?{entry:{origin:native.entry.origin,username:native.entry.username,password:'replacement-fixture-only',expires:Date.now()+180000}}:{ok:true});
  render(<Frame/>);await screen.findByLabelText('Sharing passphrase');
  fireEvent.change(screen.getByLabelText('Sharing passphrase'),{target:{value:native.password}});fireEvent.click(screen.getByRole('button',{name:'Unlock'}));
  fireEvent.click(await screen.findByRole('button',{name:'Encrypt and save login'},{timeout:10000}));
  const replace=await screen.findByRole('button',{name:'Website accepted it — update saved login'});
  expect(fetcher.mock.calls.some(([,options])=>options.method==='POST')).toBe(false);
  fireEvent.click(replace);await screen.findByRole('heading',{name:'Encrypted and saved'});
  const sent=fetcher.mock.calls.find(([,options])=>options.method==='POST')[1].body;
  expect(JSON.parse(sent).envelope).toMatchObject({context:native.team.id,epoch:1});
  expect(sent).not.toContain('replacement-fixture-only');expect(sent).not.toContain(native.password);expect(sent).not.toContain(native.entry.origin);
},15000);
