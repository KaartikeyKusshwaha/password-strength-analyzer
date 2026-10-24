import {beforeEach,expect,it,vi} from 'vitest';
import {act,fireEvent,render,screen,waitFor} from '@testing-library/react';
import TeamVaults from './TeamVaults';
import {unlockSharingIdentity,verifyTeam,prepareSharingPassphraseChange,openTeamVault,ownershipStateDigest,prepareOwnershipProposal,acceptOwnershipTransfer} from './sharing-crypto';
vi.mock('./sharing-crypto',()=>({canonical:value=>JSON.stringify(value),unlockSharingIdentity:vi.fn(),prepareSharingPassphraseChange:vi.fn(),createSharingIdentity:vi.fn(),createTeamVault:vi.fn(),verifyTeam:vi.fn(),openTeamVault:vi.fn(),rotateTeamVault:vi.fn(),ownershipStateDigest:vi.fn(),prepareOwnershipProposal:vi.fn(),acceptOwnershipTransfer:vi.fn()}));
vi.mock('./strength',()=>({estimator:{check:()=>({score:4})}}));
const me={id:'b'.repeat(24),workspace:'c'.repeat(24),role:'viewer'},owner='a'.repeat(24),vault='d'.repeat(24),fingerprint='1'.repeat(64);
let fetcher;
beforeEach(()=>{
  vi.clearAllMocks();
  unlockSharingIdentity.mockResolvedValue({user:me.id,fingerprint:'2'.repeat(64)});verifyTeam.mockResolvedValue({fingerprint});
  fetcher=vi.fn(async(url,options)=>({ok:true,json:async()=>url==='/api/sharing/identity'?{identity:{encrypted:{ciphertext:'opaque'},public:{},fingerprint:'2'.repeat(64)}}:url==='/api/sharing/directory'?{members:[]}:url==='/api/team-vaults'?{vaults:[{id:vault,name:'Client Alpha',role:'viewer',accepted:false}]}:url.endsWith('/accept')?{ok:true}:{id:vault,owner,owner_fingerprint:fingerprint,workspace:me.workspace,name:'Client Alpha',role:'viewer',accepted:false,epoch:1,revision:1,payload:null}}));
  vi.stubGlobal('fetch',fetcher);
});
async function unlock() {
  render(<TeamVaults me={me}/>);await screen.findByRole('button',{name:'Unlock sharing identity'});
  fireEvent.change(screen.getByLabelText('Sharing passphrase'),{target:{value:'fixture-only-passphrase-never-sent'}});fireEvent.click(screen.getByRole('button',{name:'Unlock sharing identity'}));await screen.findByText('Your identity fingerprint · share through a trusted channel');
}
it('keeps the sharing passphrase local and locks when the tab becomes hidden',async()=>{
  await unlock();expect(unlockSharingIdentity).toHaveBeenCalledWith(me.id,expect.anything(),'fixture-only-passphrase-never-sent');
  expect(JSON.stringify(fetcher.mock.calls)).not.toContain('fixture-only-passphrase');
  Object.defineProperty(document,'hidden',{configurable:true,value:true});fireEvent(document,new Event('visibilitychange'));
  await screen.findByRole('button',{name:'Unlock sharing identity'});Object.defineProperty(document,'hidden',{configurable:true,value:false});
});
it('verifies the owner fingerprint before accepting an invitation and leaves content locked',async()=>{
  await unlock();fireEvent.click(screen.getByRole('button',{name:'Client Alpha · viewer · invitation'}));await screen.findByLabelText('Verified owner fingerprint');
  fireEvent.change(screen.getByLabelText('Verified owner fingerprint'),{target:{value:fingerprint}});fireEvent.click(screen.getByRole('button',{name:'Verify and accept invitation'}));
  await waitFor(()=>expect(fetcher.mock.calls.some(([url])=>url.endsWith('/accept'))).toBe(true));
  expect(verifyTeam).toHaveBeenCalledWith(expect.objectContaining({payload:null}),expect.anything(),fingerprint);
  expect(screen.queryByRole('button',{name:'Encrypt and save account'})).not.toBeInTheDocument();
});

function changePassphrase() {
  fireEvent.change(screen.getByLabelText('Current sharing passphrase'),{target:{value:'fixture-current-sharing-passphrase'}});
  fireEvent.change(screen.getByLabelText('New sharing passphrase'),{target:{value:'fixture-new-sharing-passphrase'}});
  fireEvent.change(screen.getByLabelText('Confirm new sharing passphrase'),{target:{value:'fixture-new-sharing-passphrase'}});
  fireEvent.click(screen.getByRole('button',{name:'Change sharing passphrase and lock'}));
}
it('changes protection locally, clears fields before crypto and locks after the encrypted write',async()=>{
  const body={previous_digest:'3'.repeat(64),encrypted:{ciphertext:'new-opaque-envelope'},signature:'fixture-signature'};
  prepareSharingPassphraseChange.mockResolvedValue(body);
  await unlock();changePassphrase();
  expect(screen.getByLabelText('New sharing passphrase')).toHaveValue('');
  expect(await screen.findByRole('status')).toHaveTextContent('Sharing passphrase changed');
  expect(prepareSharingPassphraseChange).toHaveBeenCalledWith(me.id,expect.objectContaining({fingerprint:'2'.repeat(64)}),'fixture-current-sharing-passphrase','fixture-new-sharing-passphrase');
  const writes=fetcher.mock.calls.filter(([url])=>url==='/api/sharing/identity/passphrase');
  expect(writes).toHaveLength(1);expect(JSON.parse(writes[0][1].body)).toEqual(body);
  expect(JSON.stringify(fetcher.mock.calls)).not.toContain('fixture-new-sharing-passphrase');
  expect(JSON.stringify(fetcher.mock.calls)).not.toContain('fixture-current-sharing-passphrase');
  expect(screen.getByRole('button',{name:'Unlock sharing identity'})).toBeInTheDocument();
});
it('does not submit a rewrap when locking interrupts local encryption',async()=>{
  let finish;prepareSharingPassphraseChange.mockImplementation(()=>new Promise(resolve=>{finish=resolve;}));
  await unlock();changePassphrase();
  await waitFor(()=>expect(prepareSharingPassphraseChange).toHaveBeenCalled());
  fireEvent.click(screen.getByRole('button',{name:'Lock shared vaults'}));
  finish({previous_digest:'3'.repeat(64),encrypted:{ciphertext:'late'},signature:'late'});
  await screen.findByRole('button',{name:'Unlock sharing identity'});
  await waitFor(()=>expect(screen.getByRole('button',{name:'Unlock sharing identity'})).not.toBeDisabled());
  expect(fetcher.mock.calls.some(([url])=>url==='/api/sharing/identity/passphrase')).toBe(false);
});
it('does not publish a completed rewrap into a newer lock session',async()=>{
  let finish;prepareSharingPassphraseChange.mockResolvedValue({previous_digest:'3'.repeat(64),encrypted:{ciphertext:'new'},signature:'fixture'});
  const original=fetcher.getMockImplementation();
  fetcher.mockImplementation((url,options)=>url==='/api/sharing/identity/passphrase'?new Promise(resolve=>{finish=()=>resolve({ok:true,json:async()=>({shared_connections_revoked:true})});}):original(url,options));
  await unlock();changePassphrase();
  await waitFor(()=>expect(finish).toBeTypeOf('function'));
  fireEvent.click(screen.getByRole('button',{name:'Lock shared vaults'}));finish();
  await screen.findByRole('button',{name:'Unlock sharing identity'});
  await waitFor(()=>expect(screen.getByRole('button',{name:'Unlock sharing identity'})).not.toBeDisabled());
  expect(screen.queryByText(/Sharing passphrase changed/)).not.toBeInTheDocument();
});
it('rejects mismatched confirmation before preparing or sending a wrapper',async()=>{
  await unlock();
  fireEvent.change(screen.getByLabelText('Current sharing passphrase'),{target:{value:'fixture-current-sharing-passphrase'}});
  fireEvent.change(screen.getByLabelText('New sharing passphrase'),{target:{value:'fixture-new-sharing-passphrase'}});
  fireEvent.change(screen.getByLabelText('Confirm new sharing passphrase'),{target:{value:'fixture-different-sharing-passphrase'}});
  fireEvent.click(screen.getByRole('button',{name:'Change sharing passphrase and lock'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('must match');
  expect(prepareSharingPassphraseChange).not.toHaveBeenCalled();
  expect(screen.getByLabelText('Current sharing passphrase')).toHaveValue('');
});
it('locks an already-open sharing identity when another session changes protection',async()=>{
  const intervals=vi.spyOn(globalThis,'setInterval');
  await unlock();
  const original=fetcher.getMockImplementation();
  fetcher.mockImplementation((url,options)=>url==='/api/sharing/identity'?Promise.resolve({ok:true,json:async()=>({identity:{public:{},fingerprint:'2'.repeat(64),encrypted:{ciphertext:'changed-in-another-session'}}})}):original(url,options));
  await waitFor(()=>expect(intervals.mock.calls.some(([,delay])=>delay===8000)).toBe(true));
  const poll=intervals.mock.calls.filter(([,delay])=>delay===8000).at(-1)[0];
  await act(async()=>{await poll();});
  expect(screen.getByRole('button',{name:'Unlock sharing identity'})).toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('changed in another session');
  expect(screen.queryByRole('button',{name:'Change sharing passphrase and lock'})).not.toBeInTheDocument();
});
it('fetches current identity protection on the next unlock after a response arrives while locked',async()=>{
  let finish;prepareSharingPassphraseChange.mockResolvedValue({previous_digest:'3'.repeat(64),encrypted:{ciphertext:'new'},signature:'fixture'});
  const original=fetcher.getMockImplementation();
  let changed=false;
  fetcher.mockImplementation((url,options)=>{
    if(url==='/api/sharing/identity/passphrase')return new Promise(resolve=>{finish=()=>{changed=true;resolve({ok:true,json:async()=>({shared_connections_revoked:true})});};});
    if(url==='/api/sharing/identity' && changed)return Promise.resolve({ok:true,json:async()=>({identity:{public:{},fingerprint:'2'.repeat(64),encrypted:{ciphertext:'new-from-server'}}})});
    return original(url,options);
  });
  await unlock();changePassphrase();
  await waitFor(()=>expect(finish).toBeTypeOf('function'));
  fireEvent.click(screen.getByRole('button',{name:'Lock shared vaults'}));finish();
  await waitFor(()=>expect(screen.getByRole('button',{name:'Unlock sharing identity'})).not.toBeDisabled());
  fireEvent.change(screen.getByLabelText('Sharing passphrase'),{target:{value:'fixture-new-sharing-passphrase'}});
  fireEvent.click(screen.getByRole('button',{name:'Unlock sharing identity'}));
  await screen.findByText('Your identity fingerprint · share through a trusted channel');
  expect(unlockSharingIdentity).toHaveBeenLastCalledWith(me.id,expect.objectContaining({encrypted:{ciphertext:'new-from-server'}}),'fixture-new-sharing-passphrase');
});

async function openOwnershipPage(asOwner) {
  const other='f'.repeat(24),current={...me,role:'analyst'},role=asOwner?'owner':'editor';
  const team={id:vault,owner:asOwner?me.id:other,workspace:me.workspace,owner_fingerprint:fingerprint,name:'Client handoff',role,accepted:true,epoch:1,revision:1,rotation_required:false,browser_policy:{},grants:[{user_id:me.id,email:'fixture@example.test',role,accepted:true},{user_id:other,email:'other@example.test',role:asOwner?'editor':'owner',accepted:true}]};
  const proposal={id:'e'.repeat(24),status:'pending',document:{vault_id:vault,owner:team.owner,recipient:me.id,former_owner_role:'removed',expires_at:Math.floor(Date.now()/1000)+900}};
  ownershipStateDigest.mockResolvedValue('same-current-state');
  openTeamVault.mockResolvedValue({handle:{close:vi.fn()},entries:[]});
  fetcher.mockImplementation(async(url,options)=>({ok:true,json:async()=>{
    if(url==='/api/sharing/identity')return {identity:{encrypted:{ciphertext:'opaque'},public:{},fingerprint:'2'.repeat(64)}};
    if(url==='/api/sharing/directory')return {members:[{id:me.id,email:'fixture@example.test',role:'analyst',public:{}},{id:other,email:'other@example.test',role:'reviewer',public:{}}]};
    if(url==='/api/team-vaults')return {vaults:[team]};
    if(url==='/api/team-vaults/'+vault)return team;
    if(url.endsWith('/ownership'))return {proposal:asOwner?null:proposal};
    if(url==='/api/account-actions')return {actions:[]};
    return {};
  }}));
  render(<TeamVaults me={current}/>);
  await screen.findByRole('button',{name:'Unlock sharing identity'});
  fireEvent.change(screen.getByLabelText('Sharing passphrase'),{target:{value:'fixture-sharing-passphrase'}});fireEvent.click(screen.getByRole('button',{name:'Unlock sharing identity'}));
  fireEvent.click(await screen.findByRole('button',{name:'Client handoff · '+role}));
  await screen.findByRole('button',{name:'Verify and open shared vault'});
  if(!asOwner)fireEvent.change(screen.getByLabelText('Verified owner fingerprint'),{target:{value:fingerprint}});
  fireEvent.click(screen.getByRole('button',{name:'Verify and open shared vault'}));
  fireEvent.click(await screen.findByText('Vault ownership and handoff'));
  return {other,proposal};
}
it('does not submit a late ownership proposal after shared vaults are locked',async()=>{
  let finish;prepareOwnershipProposal.mockImplementation(()=>new Promise(resolve=>{finish=resolve;}));
  const {other}=await openOwnershipPage(true);
  await screen.findByRole('button',{name:'Sign ownership proposal'});
  fireEvent.change(screen.getByLabelText('New vault owner'),{target:{value:other}});
  fireEvent.change(screen.getByLabelText('Your access after transfer'),{target:{value:'removed'}});
  fireEvent.click(screen.getByRole('button',{name:'Sign ownership proposal'}));
  await waitFor(()=>expect(finish).toBeTypeOf('function'));
  fireEvent.click(screen.getByRole('button',{name:'Lock shared vaults'}));
  await act(async()=>{finish({document:{},signature:'fixture'});});
  expect(fetcher.mock.calls.some(([url,options])=>url.endsWith('/ownership') && options.method==='POST')).toBe(false);
});
it('does not submit a late ownership acceptance after shared vaults are locked',async()=>{
  let finish;acceptOwnershipTransfer.mockImplementation(()=>new Promise(resolve=>{finish=resolve;}));
  await openOwnershipPage(false);
  await screen.findByRole('button',{name:'Accept ownership and rotate vault key'});
  fireEvent.click(screen.getByLabelText('I accept ownership, the listed member access and replacing this vault’s encryption key.'));
  fireEvent.click(screen.getByRole('button',{name:'Accept ownership and rotate vault key'}));
  await waitFor(()=>expect(finish).toBeTypeOf('function'));
  fireEvent.click(screen.getByRole('button',{name:'Lock shared vaults'}));
  await act(async()=>{finish({signature:'fixture'});});
  expect(fetcher.mock.calls.some(([url,options])=>url.endsWith('/ownership/accept') && options.method==='POST')).toBe(false);
});
