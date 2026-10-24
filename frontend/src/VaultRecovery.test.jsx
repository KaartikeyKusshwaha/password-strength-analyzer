import {beforeEach,expect,it,vi} from 'vitest';
import {act,fireEvent,render,screen,waitFor} from '@testing-library/react';
import VaultRecovery from './VaultRecovery';
import {api} from './api';
import {parseRecoveryKit,prepareRecoveryKit,recoverWithKit} from './vault-v2';
vi.mock('./api',()=>({api:vi.fn()}));
vi.mock('./vault-v2',()=>({parseRecoveryKit:vi.fn(),prepareRecoveryKit:vi.fn(),recoverWithKit:vi.fn(),rotateProtectedVault:vi.fn()}));
vi.mock('./strength',()=>({estimator:{check:()=>({score:4})}}));
const secret='SRK1-00010203-04050607-08090A0B-0C0D0E0F-10111213-14151617-18191A1B-1C1D1E1F',space={id:'a'.repeat(24),lock_seconds:180};
const envelope={version:2,context:space.id,ciphertext:'opaque-encrypted-fixture'},kit={vault_id:space.id,recovery_id:'b'.repeat(24),created_at:'2026-10-21T00:00:00.000Z',snapshot:envelope};
beforeEach(()=>{
  api.mockReset().mockResolvedValue({envelope,revision:3});prepareRecoveryKit.mockReset().mockResolvedValue({envelope,kit,secret});recoverWithKit.mockReset().mockResolvedValue(envelope);parseRecoveryKit.mockReset().mockReturnValue(kit);
  vi.stubGlobal('URL',Object.assign(URL,{createObjectURL:vi.fn(()=> 'blob:fixture'),revokeObjectURL:vi.fn()}));
  vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{});
});
async function prepared() {
  fireEvent.click(screen.getByRole('button',{name:'Prepare recovery kit'}));
  fireEvent.change(screen.getByLabelText('Master passphrase for recovery setup'),{target:{value:'private-fixture-current-master'}});
  fireEvent.submit(screen.getByLabelText('Master passphrase for recovery setup').closest('form'));
  await screen.findByRole('heading',{name:'Prepared, not activated'});
}
async function setupReady() {
  await prepared();fireEvent.click(screen.getByRole('button',{name:'Download encrypted recovery kit'}));
  fireEvent.change(screen.getByLabelText('Retype or paste the saved recovery key'),{target:{value:secret}});
  fireEvent.click(screen.getByLabelText(/I verified the kit file was saved/));
}
it('keeps prepared material local until file/key confirmation and sends only a revision-bound encrypted rotation',async()=>{
  const changed=vi.fn();render(<VaultRecovery space={space} vaultPath="/vault?vault_id=fixture" unlocked onReplaced={changed}/>);
  await prepared();expect(screen.getByRole('button',{name:'Activate recovery kit'})).toBeDisabled();
  expect(api.mock.calls.filter(([,body])=>body)).toHaveLength(0);
  fireEvent.click(screen.getByRole('button',{name:'Download encrypted recovery kit'}));
  fireEvent.change(screen.getByLabelText('Retype or paste the saved recovery key'),{target:{value:secret}});
  fireEvent.click(screen.getByLabelText(/I verified the kit file was saved/));
  api.mockResolvedValueOnce({revision:4});fireEvent.click(screen.getByRole('button',{name:'Activate recovery kit'}));
  await waitFor(()=>expect(changed).toHaveBeenCalled());
  const body=api.mock.calls.find(([,body])=>body)[1];expect(body).toEqual({revision:3,envelope,rotation_reason:'recovery-kit'});
  expect(JSON.stringify(body)).not.toContain(secret);expect(JSON.stringify(body)).not.toContain('private-fixture-current-master');
  expect(screen.queryByLabelText('New recovery key')).not.toBeInTheDocument();
});
it('clears a hidden preparation and never commits late crypto results',async()=>{
  let complete;prepareRecoveryKit.mockImplementation(()=>new Promise(resolve=>{complete=resolve;}));
  const changed=vi.fn();render(<VaultRecovery space={space} vaultPath="/vault" unlocked onReplaced={changed}/>);
  fireEvent.click(screen.getByRole('button',{name:'Prepare recovery kit'}));
  fireEvent.change(screen.getByLabelText('Master passphrase for recovery setup'),{target:{value:'private-fixture-master'}});
  fireEvent.submit(screen.getByLabelText('Master passphrase for recovery setup').closest('form'));
  await waitFor(()=>expect(complete).toBeTypeOf('function'));
  Object.defineProperty(document,'hidden',{configurable:true,value:true});fireEvent(document,new Event('visibilitychange'));
  await act(async()=>complete({kit,envelope,secret}));
  expect(screen.queryByLabelText('New recovery key')).not.toBeInTheDocument();expect(api.mock.calls.filter(([,body])=>body)).toHaveLength(0);
  expect(changed).not.toHaveBeenCalled();Object.defineProperty(document,'hidden',{configurable:true,value:false});
});
it('does not re-open or expose secrets after an activation response arrives following cancellation',async()=>{
  let complete;const changed=vi.fn();render(<VaultRecovery space={space} vaultPath="/vault" unlocked onReplaced={changed}/>);
  await setupReady();api.mockImplementationOnce(()=>new Promise(resolve=>{complete=resolve;}));
  fireEvent.click(screen.getByRole('button',{name:'Activate recovery kit'}));await waitFor(()=>expect(complete).toBeTypeOf('function'));
  fireEvent.click(screen.getByRole('button',{name:'Close recovery panel and clear local secrets'}));await act(async()=>complete({revision:4}));
  expect(changed).not.toHaveBeenCalled();expect(screen.queryByLabelText('New recovery key')).not.toBeInTheDocument();
});
it('recovering while locked uses the selected source and excludes passwords, code and kit from the server request',async()=>{
  const changed=vi.fn();render(<VaultRecovery space={space} vaultPath="/vault" unlocked={false} onReplaced={changed}/>);
  expect(screen.getByRole('button',{name:'Prepare recovery kit'})).toBeDisabled();
  fireEvent.click(screen.getByRole('button',{name:'Recover with a kit'}));
  const file=new File(['encrypted-fixture'], 'recovery.json',{type:'application/json'});Object.defineProperty(file,'text',{value:async()=> 'encrypted-fixture'});
  fireEvent.change(screen.getByLabelText('Recovery-kit JSON'),{target:{files:[file]}});
  await screen.findByText(/Kit snapshot:/);
  fireEvent.change(screen.getByLabelText('Saved recovery key'),{target:{value:secret}});
  fireEvent.change(screen.getByLabelText('Recovery source'),{target:{value:'snapshot'}});
  fireEvent.change(screen.getByLabelText('Recovery new master passphrase'),{target:{value:'private-new-master-fixture'}});
  fireEvent.change(screen.getByLabelText('Confirm recovery new master passphrase'),{target:{value:'private-new-master-fixture'}});
  api.mockResolvedValueOnce({envelope,revision:3}).mockResolvedValueOnce({revision:4});
  fireEvent.submit(screen.getByLabelText('Saved recovery key').closest('form'));
  await waitFor(()=>expect(changed).toHaveBeenCalled());
  expect(recoverWithKit).toHaveBeenCalledWith(kit,secret,'private-new-master-fixture',{context:space.id,currentEnvelope:envelope,source:'snapshot'});
  const body=api.mock.calls.find(([,body])=>body)[1];expect(body).toEqual({revision:3,envelope,rotation_reason:'recovery-snapshot'});
  expect(JSON.stringify(body)).not.toContain(secret);expect(JSON.stringify(body)).not.toContain('private-new-master-fixture');
});
