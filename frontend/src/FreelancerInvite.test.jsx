import React from 'react';
import {it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import FreelancerInvite from '../../companion/extension/FreelancerInvite';
import {signFreelancerVault} from '../../companion/extension/freelancer-invitation';
vi.mock('../../companion/extension/freelancer-invitation',()=>({signFreelancerVault:vi.fn()}));
const client='a'.repeat(24),person='b'.repeat(24),vault='c'.repeat(24),actor='d'.repeat(24);
const map={clients:[{id:client,name:'Client'}],people:[{id:person,email:'freelancer@example.test',role:'reviewer'}],systems:[{id:vault,name:'Client logins'}],actor_id:actor};
const draft={id:'e'.repeat(24),status:'pending',deadline:Date.now()/1000+900,plan_digest:'f'.repeat(64),plan:{person,role:'editor',expires_at:1900000000,vaults:[{vault}]}};
it('stages local wrapped invitations and requires a separate authenticated atomic apply',async()=>{
 const signed={vault_id:vault,token:'secret-fixture-token',grant:{signature:'signed'}},connection={origin:'https://service.example.test'},session={};signFreelancerVault.mockResolvedValue(signed);const request=vi.fn(async(_,path)=>path==='invitations'?draft:{ok:true,note:'Invitations and expiry created.'});render(<FreelancerInvite connection={connection} map={map} session={session} selectedVault={{vaultId:vault}} unlocked request={request}/>);
 fireEvent.change(screen.getByLabelText('Invitation client'),{target:{value:client}});fireEvent.change(screen.getByLabelText('Freelancer teammate'),{target:{value:person}});fireEvent.click(screen.getByRole('button',{name:'Prepare invitation and expiry'}));
 fireEvent.click(await screen.findByRole('button',{name:'Sign invitation for selected vault'}));await screen.findByRole('button',{name:'Grant invitations and approve expiry'});expect(request).toHaveBeenCalledTimes(1);fireEvent.change(screen.getByLabelText('Current account password'),{target:{value:'fixture-only'}});fireEvent.change(screen.getByLabelText('Unused MFA or recovery code'),{target:{value:'123456'}});fireEvent.click(screen.getByLabelText(/I approve this teammate/));fireEvent.click(screen.getByRole('button',{name:'Grant invitations and approve expiry'}));
 await waitFor(()=>expect(request).toHaveBeenCalledWith(connection,'invitations/'+draft.id+'/apply',{plan_digest:draft.plan_digest,confirmed:true,password:'fixture-only',code:'123456',vaults:[signed]}));expect(await screen.findByRole('status')).toHaveTextContent('Invitations and expiry created.');expect(screen.queryByLabelText('Current account password')).not.toBeInTheDocument();expect(screen.queryByText('secret-fixture-token')).not.toBeInTheDocument();
});
