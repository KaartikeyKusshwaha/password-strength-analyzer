import {expect,it,vi} from 'vitest';
import {act,fireEvent,render,screen,waitFor} from '@testing-library/react';
import Vault from './Vault';
const mocks=vi.hoisted(()=>({unlock:vi.fn(),encrypt:vi.fn(),changeMaster:vi.fn(),createProtected:vi.fn()}));
vi.mock('./vault-crypto',async original=>({...await original(),unlockVault:mocks.unlock,encryptVault:mocks.encrypt}));
vi.mock('./strength',()=>({estimator:{check:()=>({score:4})}}));
vi.mock('./vault-v2',()=>({changeMasterPassphrase:mocks.changeMaster,createProtectedVault:mocks.createProtected}));
const payload={version:1,ciphertext:'opaque-fixture-ciphertext'},space={id:'b'.repeat(24),name:'Fixture vault',lock_seconds:180,browser_enabled:true,browser_save:true,browser_fill:true},me={id:'c'.repeat(24)};
const entry={id:'fixture-login',type:'login',title:'Fixture account',origin:'https://example.test',username:'fixture',password:'old-fixture-password',pending_change:{action_id:'a'.repeat(24),password:'proposed-fixture-password',created_at:'2026-10-19T12:00:00.000Z'}};
function response(value) {return {ok:true,json:async()=>value};}
async function begin() {render(<Vault space={space} me={me}/>);await screen.findByRole('button',{name:'Unlock vault'});fireEvent.change(screen.getByLabelText('Master passphrase'),{target:{value:'fixture-only-master-passphrase'}});fireEvent.click(screen.getByRole('button',{name:'Unlock vault'}));}
function masterForm(){
  fireEvent.change(screen.getByLabelText('Current vault master passphrase'),{target:{value:'fixture-only-master-passphrase'}});
  fireEvent.change(screen.getByLabelText('New vault master passphrase'),{target:{value:'fixture-only-new-master-passphrase'}});
  fireEvent.change(screen.getByLabelText('Confirm new vault master passphrase'),{target:{value:'fixture-only-new-master-passphrase'}});
}
it('removes plaintext export on lock and requires new approval after unlocking again',async()=>{
  mocks.unlock.mockResolvedValue({key:{},salt:[],entries:[entry]});
  vi.stubGlobal('fetch',vi.fn(async url=>response(url==='/api/account-actions'?{actions:[]}:{envelope:payload,revision:1})));
  await begin();fireEvent.click(await screen.findByText('Move logins to another password manager'));
  fireEvent.click(screen.getByLabelText(/I understand this downloads plaintext/));
  expect(screen.getByRole('button',{name:'Download plaintext login CSV'})).toBeEnabled();
  fireEvent.click(screen.getByRole('button',{name:'Lock'}));
  expect(screen.queryByText('Move logins to another password manager')).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Master passphrase'),{target:{value:'fixture-only-master-passphrase'}});
  fireEvent.click(screen.getByRole('button',{name:'Unlock vault'}));
  fireEvent.click(await screen.findByText('Move logins to another password manager'));
  expect(screen.getByRole('button',{name:'Download plaintext login CSV'})).toBeDisabled();
});
it('does not restore a late unlock after the tab was hidden',async()=>{
  let complete;mocks.unlock.mockImplementation(()=>new Promise(resolve=>{complete=resolve;}));
  vi.stubGlobal('fetch',vi.fn(async()=>response({envelope:payload,revision:1})));
  await begin();await waitFor(()=>expect(complete).toBeTypeOf('function'));
  Object.defineProperty(document,'hidden',{configurable:true,value:true});fireEvent(document,new Event('visibilitychange'));
  complete({key:{},salt:[],entries:[entry]});await waitFor(()=>expect(screen.getByRole('button',{name:'Unlock vault'})).not.toBeDisabled());
  expect(screen.queryByRole('button',{name:'Lock'})).not.toBeInTheDocument();Object.defineProperty(document,'hidden',{configurable:true,value:false});
});
it('does not reopen the vault with a late save response after Lock',async()=>{
  let completeSave;mocks.unlock.mockResolvedValue({key:{},salt:[],entries:[entry]});mocks.encrypt.mockResolvedValue(payload);
  const fetcher=vi.fn(async(url,options)=>url==='/api/account-actions'?response({actions:[]}):options.body?new Promise(resolve=>{completeSave=()=>resolve(response({revision:2}));}):response({envelope:payload,revision:1}));vi.stubGlobal('fetch',fetcher);
  await begin();fireEvent.click(await screen.findByRole('button',{name:'Website accepted it — use staged password'}));await waitFor(()=>expect(completeSave).toBeTypeOf('function'));
  fireEvent.click(screen.getByRole('button',{name:'Lock'}));completeSave();await screen.findByRole('button',{name:'Unlock vault'});
  expect(screen.queryByRole('button',{name:'Lock'})).not.toBeInTheDocument();expect(screen.queryByText('proposed-fixture-password')).not.toBeInTheDocument();
});
it('cancels a master rewrap that completes after the user locks the vault',async()=>{
  let complete;mocks.unlock.mockResolvedValue({key:{},salt:{version:2},entries:[entry]});
  mocks.changeMaster.mockImplementation(()=>new Promise(resolve=>{complete=resolve;}));
  const fetcher=vi.fn(async(url,options)=>url==='/api/account-actions'?response({actions:[]}):options.body?response({revision:2}):response({envelope:{...payload,version:2},revision:1}));vi.stubGlobal('fetch',fetcher);
  await begin();await screen.findByRole('button',{name:'Update vault protection'});masterForm();fireEvent.click(screen.getByRole('button',{name:'Update vault protection'}));
  await waitFor(()=>expect(complete).toBeTypeOf('function'));fireEvent.click(screen.getByRole('button',{name:'Lock'}));
  await act(async()=>complete({...payload,version:2}));
  await waitFor(()=>expect(screen.getByRole('button',{name:'Unlock vault'})).not.toBeDisabled());
  expect(fetcher.mock.calls.filter(([,options])=>options.body)).toHaveLength(0);
  expect(screen.queryByText(/Vault protection updated/)).not.toBeInTheDocument();
});
it('cancels a legacy encryption upgrade when locking during key derivation',async()=>{
  let complete;mocks.unlock.mockResolvedValue({key:{},salt:[],entries:[entry]});
  mocks.createProtected.mockImplementation(()=>new Promise(resolve=>{complete=resolve;}));
  const fetcher=vi.fn(async(url,options)=>url==='/api/account-actions'?response({actions:[]}):options.body?response({revision:2}):response({envelope:payload,revision:1}));vi.stubGlobal('fetch',fetcher);
  await begin();await screen.findByRole('button',{name:'Upgrade encrypted vault'});masterForm();fireEvent.click(screen.getByRole('button',{name:'Upgrade encrypted vault'}));
  await waitFor(()=>expect(complete).toBeTypeOf('function'));fireEvent.click(screen.getByRole('button',{name:'Lock'}));await act(async()=>complete({envelope:{...payload,version:2}}));
  await screen.findByRole('button',{name:'Unlock vault'});
  expect(fetcher.mock.calls.filter(([,options])=>options.body)).toHaveLength(0);
});
it('cancels a cross-vault copy while destination encryption is in progress',async()=>{
  let complete;mocks.unlock.mockResolvedValue({key:{},salt:[],entries:[entry]});mocks.encrypt.mockImplementation(()=>new Promise(resolve=>{complete=resolve;}));
  const fetcher=vi.fn(async(url,options)=>url==='/api/account-actions'?response({actions:[]}):options.body?response({revision:2}):response({envelope:payload,revision:1}));vi.stubGlobal('fetch',fetcher);
  render(<Vault space={space} me={me} otherVaults={[{id:'d'.repeat(24),name:'Destination'}]}/>);
  await screen.findByRole('button',{name:'Unlock vault'});fireEvent.change(screen.getByLabelText('Master passphrase'),{target:{value:'fixture-only-master-passphrase'}});fireEvent.click(screen.getByRole('button',{name:'Unlock vault'}));
  await screen.findByRole('button',{name:'Encrypt a copy in destination'});fireEvent.change(screen.getByLabelText('Destination master passphrase'),{target:{value:'fixture-only-destination-master'}});fireEvent.click(screen.getByRole('button',{name:'Encrypt a copy in destination'}));
  await waitFor(()=>expect(complete).toBeTypeOf('function'));fireEvent.click(screen.getByRole('button',{name:'Lock'}));await act(async()=>complete(payload));
  await screen.findByRole('button',{name:'Unlock vault'});
  expect(fetcher.mock.calls.filter(([,options])=>options.body)).toHaveLength(0);
  expect(screen.queryByText(/Encrypted copy saved/)).not.toBeInTheDocument();
});
it('does not restore old backup entries into a newer unlock session',async()=>{
  let complete;mocks.unlock.mockResolvedValueOnce({key:{},salt:[],entries:[entry]}).mockImplementationOnce(()=>new Promise(resolve=>{complete=resolve;})).mockResolvedValue({key:{},salt:[],entries:[entry]});
  mocks.encrypt.mockResolvedValue(payload);
  const fetcher=vi.fn(async(url,options)=>url==='/api/account-actions'?response({actions:[]}):options.body?response({revision:2}):response({envelope:payload,revision:1}));vi.stubGlobal('fetch',fetcher);
  await begin();const master=await screen.findByLabelText(/Backup.s master passphrase/),file=new File(['opaque-fixture'], 'fixture.json',{type:'application/json'});
  Object.defineProperty(file,'text',{value:async()=>JSON.stringify({envelope:payload})});
  fireEvent.change(screen.getByLabelText('Encrypted backup'),{target:{files:[file]}});fireEvent.change(master,{target:{value:'fixture-only-backup-master'}});
  fireEvent.submit(master.closest('form'));
  await waitFor(()=>expect(complete).toBeTypeOf('function'));fireEvent.click(screen.getByRole('button',{name:'Lock'}));
  await screen.findByRole('button',{name:'Unlock vault'});fireEvent.change(screen.getByLabelText('Master passphrase'),{target:{value:'fixture-only-master-passphrase'}});fireEvent.click(screen.getByRole('button',{name:'Unlock vault'}));
  await screen.findByRole('button',{name:'Lock'});await act(async()=>complete({entries:[{...entry,id:'old-backup',password:'old-backup-fixture'}]}));
  expect(fetcher.mock.calls.filter(([,options])=>options.body)).toHaveLength(0);
  expect(screen.queryByText('old-backup-fixture')).not.toBeInTheDocument();expect(screen.getByRole('button',{name:'Lock'})).toBeInTheDocument();
});
it('updates protection normally while unlocked and clears locally entered passphrases',async()=>{
  mocks.unlock.mockResolvedValue({key:{},salt:{version:2},entries:[entry]});mocks.changeMaster.mockResolvedValue({...payload,version:2});
  const fetcher=vi.fn(async(url,options)=>url==='/api/account-actions'?response({actions:[]}):options.body?response({revision:2}):response({envelope:{...payload,version:2},revision:1}));vi.stubGlobal('fetch',fetcher);
  await begin();await screen.findByRole('button',{name:'Update vault protection'});masterForm();fireEvent.click(screen.getByRole('button',{name:'Update vault protection'}));
  expect(await screen.findByRole('status')).toHaveTextContent('Vault protection updated');
  expect(screen.getByRole('button',{name:'Unlock vault'})).toBeInTheDocument();
  const writes=fetcher.mock.calls.filter(([,options])=>options.body);expect(writes).toHaveLength(1);
  expect(JSON.parse(writes[0][1].body)).toEqual({revision:1,envelope:{...payload,version:2}});
  expect(writes[0][1].body).not.toContain('fixture-only-master');
});
it('copies to the selected destination without transferring a pending password proposal',async()=>{
  const targetId='d'.repeat(24),existing={...entry,id:'destination-existing'};
  mocks.unlock.mockResolvedValueOnce({key:{},salt:[],entries:[entry]}).mockResolvedValueOnce({key:{destination:true},salt:[],entries:[existing]});mocks.encrypt.mockResolvedValue(payload);
  const fetcher=vi.fn(async(url,options)=>url==='/api/account-actions'?response({actions:[]}):options.body?response({revision:8}):response({envelope:payload,revision:url.includes(targetId)?7:1}));vi.stubGlobal('fetch',fetcher);
  render(<Vault space={space} me={me} otherVaults={[{id:targetId,name:'Destination'}]}/>);
  await screen.findByRole('button',{name:'Unlock vault'});fireEvent.change(screen.getByLabelText('Master passphrase'),{target:{value:'fixture-only-master-passphrase'}});fireEvent.click(screen.getByRole('button',{name:'Unlock vault'}));
  const destination=await screen.findByLabelText('Destination master passphrase');fireEvent.change(destination,{target:{value:'fixture-only-destination-master'}});fireEvent.click(screen.getByRole('button',{name:'Encrypt a copy in destination'}));
  expect(await screen.findByRole('status')).toHaveTextContent('Encrypted copy saved to Destination');expect(destination).toHaveValue('');
  const writes=fetcher.mock.calls.filter(([,options])=>options.body);expect(writes).toHaveLength(1);expect(writes[0][0]).toBe('/api/vault?vault_id='+targetId);expect(JSON.parse(writes[0][1].body).revision).toBe(7);
  const encrypted=mocks.encrypt.mock.calls.at(-1)[0];expect(encrypted[0]).toEqual(existing);expect(encrypted[1].password).toBe(entry.password);expect(encrypted[1].id).not.toBe(entry.id);expect(encrypted[1].pending_change).toBeUndefined();
});
