import React from 'react';
import {it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import AccessLeases from '../../companion/extension/AccessLeases';
import {accessRequest} from '../../companion/extension/access-client';
const actor='a'.repeat(24),person='b'.repeat(24),client='c'.repeat(24),vault='d'.repeat(24);
const connection={kind:'access',origin:'https://service.example.test',token:'x'.repeat(54)};
const map={actor_id:actor,clients:[{id:client,name:'Studio client'}],systems:[{id:vault,name:'Client logins'}],people:[{id:person,email:'contractor@example.test',role:'reviewer'}],grants:[{client,person_id:person,email:'contractor@example.test',state:'accepted',source:'shared_vault_membership'}]};
const policy={id:'e'.repeat(24),client,person,created_by:actor,mode:'auto_revoke',status:'awaiting_approval',plan_digest:'f'.repeat(64),plan:{expires_at:1900000000,vaults:[{vault}]},limitations:'Selected vault memberships only.'};
it('prepares 30-day expiry by default without approving or revoking it',async()=>{
 const request=vi.fn(async(_,path,body)=>!body?{leases:[]}:{ok:true});render(<AccessLeases connection={connection} map={map} request={request}/>);
 await waitFor(()=>expect(request).toHaveBeenCalledWith(connection,'leases'));
 fireEvent.change(screen.getByLabelText('Expiry client'),{target:{value:client}});fireEvent.change(screen.getByLabelText('Contractor or departing person'),{target:{value:person}});
 fireEvent.click(screen.getByRole('button',{name:'Prepare expiry policy'}));await waitFor(()=>expect(request).toHaveBeenCalledWith(connection,'leases',expect.objectContaining({client_id:client,person_id:person,mode:'auto_revoke'})));
 const body=request.mock.calls.find(call=>call[2])[2];expect(body.expires_at).toBeGreaterThan(Date.now()/1000+29*86400);expect(body.expires_at).toBeLessThanOrEqual(Date.now()/1000+30*86400);
 expect(request.mock.calls.some(call=>call[1].endsWith('/approve'))).toBe(false);
});
it('binds a fresh expiry approval to its exact digest and clears credentials',async()=>{
 const request=vi.fn(async(_,path,body)=>!body?{leases:[policy]}:{ok:true});render(<AccessLeases connection={connection} map={map} request={request}/>);
 await screen.findByRole('heading',{name:'Studio client · awaiting approval'});fireEvent.change(screen.getByLabelText('Current account password'),{target:{value:'fixture-only'}});fireEvent.change(screen.getByLabelText('Unused MFA or recovery code'),{target:{value:'123456'}});fireEvent.click(screen.getByLabelText(/I authorize expiry removal/));fireEvent.click(screen.getByRole('button',{name:'Approve expiry policy'}));
 await waitFor(()=>expect(request).toHaveBeenCalledWith(connection,'leases/'+policy.id+'/approve',{approved:true,plan_digest:policy.plan_digest,password:'fixture-only',code:'123456'}));expect(screen.getByLabelText('Current account password')).toHaveValue('');
});
it('makes cancellation explicit and distinguishes pending key rotation',async()=>{
 const request=vi.fn(async(_,path,body)=>!body?{leases:[{...policy,status:'waiting_unlock',workflow:'f'.repeat(24),workflow_status:'waiting_unlock',reminder_sent:true}]}:{ok:true});render(<AccessLeases connection={connection} map={map} request={request}/>);
 expect(await screen.findByText(/Server memberships were removed/)).toBeInTheDocument();fireEvent.click(screen.getByRole('button',{name:'Cancel expiry policy'}));await screen.findByText('Policy and unfinished linked steps cancelled. Completed removals are not undone.');
 expect(request).toHaveBeenCalledWith(connection,'leases/'+policy.id+'/cancel',{});
});
it('keeps expiry routes separate from vault capabilities and rejects path traversal',async()=>{
 const fetcher=vi.fn(async()=>({ok:true,json:async()=>({leases:[]})}));await accessRequest(connection,'leases',undefined,fetcher);await expect(accessRequest(connection,'leases/../../vault',{},fetcher)).rejects.toThrow('Unsupported');await expect(accessRequest(connection,'leases',undefined,fetcher,{vaultToken:'v'.repeat(54)})).rejects.toThrow('limited to rotation');expect(fetcher).toHaveBeenCalledTimes(1);
});
