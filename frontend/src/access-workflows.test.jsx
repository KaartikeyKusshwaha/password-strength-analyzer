import React from 'react';
import {expect,it,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import AccessWorkflows from '../../companion/extension/AccessWorkflows';
import {accessRequest} from '../../companion/extension/access-client';

const connection={origin:'http://127.0.0.1:8110',token:'x'.repeat(54),kind:'access'};
const plan={id:'a'.repeat(24),client:'c'.repeat(24),person:'d'.repeat(24),status:'awaiting_approval',plan_digest:'e'.repeat(64),plan:{dry_run:true,vaults:[{vault:'v'}]},steps:[{id:'step',action:'revoke',status:'pending'}],coverage:'Selected memberships only.'};
const map={clients:[{id:plan.client,name:'Agency client'}],systems:[{id:'v',name:'Client logins'}],grants:[{client:plan.client,person_id:plan.person,email:'departing@example.test'}]};
function browser(){return {storage:{local:{get:vi.fn(async()=>({accessConnection:connection})),remove:vi.fn()}}};}

it('keeps approval credentials transient and binds the exact reviewed plan',async()=>{
  const request=vi.fn(async(_,path,body)=>path==='context'?map:path==='workflows'&&!body?{workflows:[plan]}:{ok:true});
  render(<AccessWorkflows browser={browser()} request={request}/>);
  await screen.findByRole('heading',{name:'Review and approve'});
  expect(screen.getByText('Client logins')).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Current account password'),{target:{value:'disposable-test-password'}});
  fireEvent.change(screen.getByLabelText('Unused MFA or recovery code'),{target:{value:'123456'}});
  fireEvent.click(screen.getByLabelText('I approve this exact preview plan.'));
  fireEvent.click(screen.getByRole('button',{name:'Approve plan'}));
  await waitFor(()=>expect(request).toHaveBeenCalledWith(connection,'workflows/'+plan.id+'/approve',{approved:true,plan_digest:plan.plan_digest,password:'disposable-test-password',code:'123456'}));
  expect(screen.getByLabelText('Current account password')).toHaveValue('');
  expect(screen.getByLabelText('Unused MFA or recovery code')).toHaveValue('');
});

it('prepares a preview by default and keeps cancellation explicit',async()=>{
  const request=vi.fn(async(_,path,body)=>path==='context'?map:path==='workflows'&&!body?{workflows:[plan]}:{ok:true});
  render(<AccessWorkflows browser={browser()} request={request}/>);
  fireEvent.change(await screen.findByLabelText('Client'),{target:{value:plan.client}});
  fireEvent.change(screen.getByLabelText('Person'),{target:{value:plan.person}});
  fireEvent.click(screen.getByRole('button',{name:'Prepare offboarding plan'}));
  await waitFor(()=>expect(request).toHaveBeenCalledWith(connection,'workflows',{client_id:plan.client,person_id:plan.person,dry_run:true}));
  await screen.findByRole('status');
  fireEvent.click(screen.getByRole('button',{name:'Cancel plan'}));
  await screen.findByText('Cancelled. Completed removals are not undone.');
});

it('disconnects the capability without retrying with the revoked token',async()=>{
  const b=browser(),request=vi.fn(async(_,path)=>path==='context'?map:path==='workflows'?{workflows:[]}:{ok:true});
  render(<AccessWorkflows browser={b} request={request}/>);
  fireEvent.click(await screen.findByRole('button',{name:'Disconnect workflows'}));
  await waitFor(()=>expect(b.storage.local.remove).toHaveBeenCalledWith('accessConnection'));
  expect(request.mock.calls.at(-1)[1]).toBe('revoke');
});

it('restricts the client to workflow routes and rejects scanner or vault capabilities',async()=>{
  const fetcher=vi.fn(async()=>({ok:true,json:async()=>({workflows:[]})}));
  await expect(accessRequest({...connection,kind:'security'},'workflows',undefined,fetcher)).rejects.toThrow('Connect access');
  await expect(accessRequest(connection,'../vault',undefined,fetcher)).rejects.toThrow('Unsupported');
  expect(fetcher).not.toHaveBeenCalled();
  await accessRequest(connection,'workflows',undefined,fetcher);
  expect(fetcher.mock.calls[0][1]).toMatchObject({credentials:'omit',redirect:'error',headers:{Authorization:'Bearer '+connection.token}});
});
