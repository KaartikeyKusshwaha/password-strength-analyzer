import React from 'react';
import {it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import ClientHandoffs from '../../companion/extension/ClientHandoffs';
import {accessRequest} from '../../companion/extension/access-client';
const actor='a'.repeat(24),receiver='b'.repeat(24),client='c'.repeat(24),person='d'.repeat(24);
const connection={kind:'access',origin:'http://127.0.0.1:8110',token:'x'.repeat(54)};
const map={actor_id:actor,clients:[{id:client,name:'Studio client'}],people:[{id:actor,role:'owner',email:'owner@example.test'},{id:receiver,role:'owner',email:'receiver@example.test'},{id:person,role:'analyst',email:'departing@example.test'}]};
const row={id:'e'.repeat(24),client,person,recipient:receiver,created_by:actor,kind:'person_handoff',status:'awaiting_approval',plan:{vaults:[{id:'v'}]},plan_digest:'f'.repeat(64),evidence:{digest:'0'.repeat(64),issues:['completed_offboarding_required'],reported_external_access:[],active_shared_password_debt:[],limitations:'External access remains unverified.'}};
it('binds approval to the reviewed handoff and clears credentials immediately',async()=>{
 const request=vi.fn(async(_,path,body)=>!body?{handoffs:[row]}:{ok:true});render(<ClientHandoffs connection={connection} map={map} runs={[]} request={request}/>);
 await screen.findByRole('heading',{name:'Studio client · awaiting approval'});
 fireEvent.change(screen.getByLabelText('Current account password'),{target:{value:'fixture-only'}});fireEvent.change(screen.getByLabelText('Unused MFA or recovery code'),{target:{value:'123456'}});
 fireEvent.click(screen.getByLabelText('I reviewed this exact scope and its current evidence.'));
 fireEvent.click(screen.getByRole('button',{name:'Approve handoff scope'}));
 await waitFor(()=>expect(request).toHaveBeenCalledWith(connection,'handoffs/'+row.id+'/approve',{confirmed:true,password:'fixture-only',code:'123456',digest:row.plan_digest}));
 expect(screen.getByLabelText('Current account password')).toHaveValue('');expect(screen.getByLabelText('Unused MFA or recovery code')).toHaveValue('');
});
it('keeps sign-off disabled while vault steps are incomplete',async()=>{
 const request=vi.fn(async()=>({handoffs:[{...row,status:'awaiting_signoff'}]}));render(<ClientHandoffs connection={connection} map={{...map,actor_id:receiver}} runs={[]} request={request}/>);
 expect(await screen.findByRole('button',{name:'Sign off handoff'})).toBeDisabled();
});
it('warns when evidence changed after a signed receipt',async()=>{
 const request=vi.fn(async()=>({handoffs:[{...row,status:'complete_with_exceptions',receipt:{at:'2026-10-23'},evidence_changed_since_signoff:true}]}));render(<ClientHandoffs connection={connection} map={map} runs={[]} request={request}/>);
 expect(await screen.findByRole('alert')).toHaveTextContent('Evidence changed after sign-off');expect(screen.queryByRole('button',{name:'Approve handoff scope'})).not.toBeInTheDocument();
});
it('permits only exact handoff capability routes',async()=>{
 const fetcher=vi.fn(async()=>({ok:true,json:async()=>({})}));await accessRequest(connection,'handoffs/'+row.id+'/signoff',{},fetcher);expect(fetcher).toHaveBeenCalledTimes(1);
 await expect(accessRequest(connection,'handoffs/../../vault',{},fetcher)).rejects.toThrow('Unsupported');expect(fetcher).toHaveBeenCalledTimes(1);
});
