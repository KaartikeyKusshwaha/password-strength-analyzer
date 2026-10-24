import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen,within,waitFor} from '@testing-library/react';
import {Popup} from '../../companion/extension/popup';
import extensionManifest from '../../companion/extension/public/manifest.json';

const fixture=vi.hoisted(()=>({instances:[]}));
vi.mock('../../companion/extension/vault-session',()=>({SaveSession:class {
  constructor(){this.generation=1;fixture.instances.push(this);}
  lock(){this.generation++;this.entries=null;}
  active(mark){if(mark!==this.generation)throw new Error('Vault locked');}
  async unlock(){this.entries=[{id:'public-fixture',type:'login',title:'Practice test',origin:'https://practice.expandtesting.com',username:'practice',password:'test-only'}];return {entries:this.entries,policy:{name:'Browser acceptance',lock_seconds:180,browser_fill:true},revision:1};}
  fill=vi.fn(async()=>this.entries[0]);
  refresh=vi.fn(async()=>{});
}}));

beforeEach(()=>{
  const connection={origin:'http://127.0.0.1:8110',token:'fixture-only'};
  fixture.instances=[];
  vi.stubGlobal('chrome',{
    storage:{local:{get:vi.fn(async()=>({connection,connections:[connection]})),set:vi.fn(),remove:vi.fn()}},
    tabs:{query:vi.fn(async()=>[{id:77,url:'https://practice.expandtesting.com/login'}]),sendMessage:vi.fn()},
    runtime:{getManifest:()=>extensionManifest,sendMessage:vi.fn()},
  });
});
afterEach(()=>{cleanup();vi.unstubAllGlobals();});

async function opened(){
  render(<Popup/>);
  fireEvent.change(await screen.findByLabelText('Master passphrase'),{target:{value:'test-only-master'}});
  fireEvent.click(screen.getByRole('button',{name:'Unlock',exact:true}));
  return (await screen.findByRole('heading',{name:'Practice test'})).closest('section');
}

it('shows progress beside the clicked entry and a receiver refusal at that same location',async()=>{
  let reply;
  chrome.tabs.sendMessage.mockImplementation(()=>new Promise(resolve=>{reply=resolve;}));
  const section=within(await opened());
  fireEvent.click(section.getByRole('button',{name:'Fill this login'}));
  expect(section.getByRole('button',{name:'Filling…'})).toBeDisabled();
  expect(section.getByRole('status')).toHaveTextContent('Checking this sign-in form');
  const version=chrome.tabs.sendMessage.mock.calls[0][1];
  expect(version.type).toBe('inspect-login');
  const manifest=await import('../../companion/extension/public/manifest.json');
  reply({ok:false,reason:'password_field',version:manifest.default.version});
  expect(await section.findByRole('alert')).toHaveTextContent('No single supported sign-in password field');
  expect(section.getByRole('button',{name:'Fill this login'})).toBeEnabled();
  expect(fixture.instances[0].fill).not.toHaveBeenCalled();
});

it('shows the fill acknowledgement beside the selected entry, without submitting the website',async()=>{
  const manifest=await import('../../companion/extension/public/manifest.json');
  chrome.tabs.sendMessage.mockResolvedValueOnce({ok:true,version:manifest.default.version}).mockResolvedValueOnce({ok:true,filled:'login'});
  const section=within(await opened());
  fireEvent.click(section.getByRole('button',{name:'Fill this login'}));
  await waitFor(()=>expect(section.getByRole('status')).toHaveTextContent('Username and password filled'));
  expect(chrome.tabs.sendMessage.mock.calls.map(([,message])=>message.type)).toEqual(['inspect-login','fill-login']);
  expect(section.getByRole('button',{name:'Fill this login'})).toBeEnabled();
});
