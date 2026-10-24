import React from 'react';
import {it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import VaultOwnership from '../../companion/extension/VaultOwnership';
import {loadConnectedOwnership,changeConnectedOwnership} from '../../companion/extension/ownership-operator';
vi.mock('../../companion/extension/ownership-operator',()=>({loadConnectedOwnership:vi.fn(),changeConnectedOwnership:vi.fn()}));
const owner='a'.repeat(24),recipient='b'.repeat(24),vault='c'.repeat(24);
const connection={origin:'https://example.test'},selectedVault={vaultKind:'shared',vaultId:vault};
const value={team:{id:vault,name:'Client accounts',owner,epoch:1,grants:[{user_id:owner,accepted:true},{user_id:recipient,accepted:true}]},directory:[{id:owner,role:'owner',email:'owner@example.test'},{id:recipient,role:'owner',email:'next@example.test'}],proposal:null};
function props(user=owner){return {connection,selectedVault,unlocked:true,session:{material:{kind:'shared',identity:{user}}},onTransferred:vi.fn()};}
it('does not load ownership information before explicit interaction or while locked',()=>{
 loadConnectedOwnership.mockClear();render(<VaultOwnership {...props()} unlocked={false}/>);expect(screen.getByText(/Select and unlock the intended shared vault/)).toBeInTheDocument();expect(loadConnectedOwnership).not.toHaveBeenCalled();
});
it('requires explicit successor and retained-role consent before signing',async()=>{
 loadConnectedOwnership.mockResolvedValue(value);changeConnectedOwnership.mockResolvedValue({});const p=props();render(<VaultOwnership {...p}/>);fireEvent.click(screen.getByRole('button',{name:'Load ownership for selected vault'}));
 fireEvent.change(await screen.findByLabelText('New vault owner'),{target:{value:recipient}});fireEvent.click(screen.getByLabelText('I approve this successor and my access after transfer.'));fireEvent.click(screen.getByRole('button',{name:'Sign ownership proposal'}));
 await waitFor(()=>expect(changeConnectedOwnership).toHaveBeenCalledWith(connection,p.session,value,'propose',recipient,'removed',undefined));
 expect(await screen.findByRole('status')).toHaveTextContent('Signed proposal ready');
});
it('shows uncertainty instead of a success message when acceptance cannot be confirmed',async()=>{
 const current={...value,proposal:{id:'d'.repeat(24),status:'pending',document:{recipient,owner,former_owner_role:'removed',expires_at:1900000000}}};loadConnectedOwnership.mockResolvedValue(current);changeConnectedOwnership.mockRejectedValue(Object.assign(new Error('Connection dropped'),{ownershipAttempted:true}));const p=props(recipient);render(<VaultOwnership {...p}/>);fireEvent.click(screen.getByRole('button',{name:'Load ownership for selected vault'}));
 fireEvent.click(await screen.findByLabelText('I accept ownership, the listed member access and replacing the encryption key.'));fireEvent.click(screen.getByRole('button',{name:'Accept ownership and rotate key'}));
 await waitFor(()=>expect(p.onTransferred).toHaveBeenCalledWith(false));expect(screen.getByRole('alert')).toHaveTextContent('Connection dropped');expect(screen.queryByRole('status')).not.toBeInTheDocument();
});
it('discards an old in-flight context after the vault is locked',async()=>{
 let finish;loadConnectedOwnership.mockImplementation(()=>new Promise(resolve=>{finish=resolve;}));const p=props(),view=render(<VaultOwnership {...p}/>);fireEvent.click(screen.getByRole('button',{name:'Load ownership for selected vault'}));view.rerender(<VaultOwnership {...p} unlocked={false}/>);finish(value);await waitFor(()=>expect(screen.queryByText('Client accounts · 2 members · key epoch 1')).not.toBeInTheDocument());
});
