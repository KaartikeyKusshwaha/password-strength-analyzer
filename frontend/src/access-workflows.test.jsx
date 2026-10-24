import React from 'react';
import {expect,it,vi} from 'vitest';
import {render,screen,fireEvent,waitFor,act} from '@testing-library/react';
import AccessWorkflows from '../../companion/extension/AccessWorkflows';
import {accessRequest} from '../../companion/extension/access-client';
import {rotateConnectedVault} from '../../companion/extension/workflow-rotation';
vi.mock('../../companion/extension/workflow-rotation',()=>({rotateConnectedVault:vi.fn()}));

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

it('distinguishes retained removal-time device observations from a live scan',async()=>{
  const snapshot={captured_at:'2026-10-23T12:00:00Z',devices:[{device:'device',platform:'macos',freshness:'stale_or_unavailable',connection_expired:true,recorded_at:'2026-10-20T12:00:00Z',checks:[{id:'filevault',state:'disabled',reason:''}]}],device_limit_reached:true,limitations:'Recorded helper self-report; no new scan.'};
  const request=vi.fn(async(_,path)=>path==='context'?map:path.endsWith('/report')?{audit:{valid:true},posture_snapshot:snapshot}:{workflows:[{...plan,status:'waiting_unlock',plan:{...plan.plan,dry_run:false}}]});
  render(<AccessWorkflows browser={browser()} request={request}/>);
  fireEvent.click(await screen.findByRole('button',{name:'View evidence report'}));
  await screen.findByRole('heading',{name:'Device evidence at removal'});
  expect(screen.getByText('macos · stale or unavailable')).toBeInTheDocument();
  expect(screen.getByText(/More than 100 devices/)).toBeInTheDocument();
  expect(screen.getByText(/Connection expired at capture/)).toBeInTheDocument();
  expect(screen.getByText('filevault: disabled')).toBeInTheDocument();
  expect(screen.getByText('Recorded helper self-report; no new scan.')).toBeInTheDocument();
});

it('makes agency tasks primary and loads only the selected specialist workflow',async()=>{
  const request=vi.fn(async(_,path)=>path==='context'?map:path==='workflows'?{workflows:[]}:{reviews:[]});
  render(<AccessWorkflows primary browser={browser()} request={request}/>);
  expect(screen.getByRole('region',{name:'Client access workflows'}).tagName).toBe('SECTION');
  await screen.findByLabelText('What needs doing?');
  expect(request.mock.calls.map(([,path])=>path)).toEqual(['context','workflows']);
  expect(screen.queryByText('Refresh weekly reviews')).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('What needs doing?'),{target:{value:'review'}});
  await screen.findByRole('button',{name:'Refresh weekly reviews'});
  expect(screen.queryByRole('button',{name:'Prepare offboarding plan'})).not.toBeInTheDocument();
  expect(screen.getByText('Weekly access review · proposed actions and sign-off').closest('details')).toHaveAttribute('open');
});

it('automatically follows an approved run to verification without resending approval or mutations',async()=>{
  let poll;
  const realInterval=globalThis.setInterval;
  const interval=vi.spyOn(globalThis,'setInterval').mockImplementation((callback,delay,...args)=>{
    if(delay===5000){poll=callback;return 123;}
    return realInterval(callback,delay,...args);
  });
  let state='queued';
  const request=vi.fn(async(_,path)=>path==='context'?map:{workflows:[{...plan,status:state,plan:{...plan.plan,dry_run:false}}]});
  try {
    render(<AccessWorkflows primary browser={browser()} request={request}/>);
    await screen.findByText(/Approved. Waiting for the server worker/);
    await waitFor(()=>expect(poll).toBeTypeOf('function'));
    state='running';await act(async()=>{await poll();});
    expect(screen.getByText(/Running approved steps automatically/)).toBeInTheDocument();
    state='waiting_unlock';await act(async()=>{await poll();});
    expect(screen.getByText(/this offboarding is not complete/)).toBeInTheDocument();
    state='complete';await act(async()=>{await poll();});
    expect(screen.getByText(/The selected vault steps are verified/)).toBeInTheDocument();
    expect(request.mock.calls.every(([,path,body])=>['context','workflows'].includes(path)&&body===undefined)).toBe(true);
  } finally {interval.mockRestore();}
});

it('continues approved rotation automatically after the matching shared vault unlocks, once per epoch',async()=>{
  rotateConnectedVault.mockReset().mockResolvedValue({ok:true});
  const vault='b'.repeat(24),session={material:{kind:'shared',epoch:2}},selected={origin:connection.origin,vaultId:vault};
  const pending={...plan,status:'waiting_unlock',plan:{dry_run:false,vaults:[{vault}]}};
  const context={...map,systems:[{id:vault,name:'Client vault',rotation_required:true}]};
  const request=vi.fn(async(_,path)=>path==='context'?context:{workflows:[pending]});
  const onRotated=vi.fn();
  const view=render(<AccessWorkflows browser={browser()} request={request} vaultSession={session} selectedVault={selected} vaultUnlocked={false} onRotated={onRotated}/>);
  await screen.findByText(/this offboarding is not complete/);
  expect(rotateConnectedVault).not.toHaveBeenCalled();
  view.rerender(<AccessWorkflows browser={browser()} request={request} vaultSession={session} selectedVault={selected} vaultUnlocked onRotated={onRotated}/>);
  await waitFor(()=>expect(onRotated).toHaveBeenCalledOnce());
  expect(rotateConnectedVault).toHaveBeenCalledWith(connection,session,plan.id,vault,request);
  fireEvent.click(screen.getByRole('button',{name:'Refresh workflows'}));
  await waitFor(()=>expect(screen.getByRole('button',{name:'Refresh workflows'})).not.toBeDisabled());
  expect(rotateConnectedVault).toHaveBeenCalledOnce();
});

it.each(['awaiting_approval','queued','dry_run','wrong_origin','personal'])('never auto-rotates an ineligible %s context',async kind=>{
  rotateConnectedVault.mockReset();
  const vault='b'.repeat(24),session={material:{kind:kind==='personal'?'personal':'shared',epoch:2}};
  const selected={origin:kind==='wrong_origin'?'https://different.example':connection.origin,vaultId:vault};
  const pending={...plan,status:['awaiting_approval','queued'].includes(kind)?kind:'waiting_unlock',plan:{dry_run:kind==='dry_run',vaults:[{vault}]}};
  const request=vi.fn(async(_,path)=>path==='context'?{...map,systems:[{id:vault,rotation_required:true}]}:{workflows:[pending]});
  render(<AccessWorkflows browser={browser()} request={request} vaultSession={session} selectedVault={selected} vaultUnlocked/>);
  await screen.findByRole('button',{name:'Refresh workflows'});
  expect(rotateConnectedVault).not.toHaveBeenCalled();
});

it('does not loop after a failed automatic rotation and allows an explicit retry',async()=>{
  rotateConnectedVault.mockReset().mockRejectedValueOnce(new Error('Vault access changed')).mockResolvedValueOnce({ok:true});
  const vault='b'.repeat(24),session={material:{kind:'shared',epoch:2}};
  const request=vi.fn(async(_,path)=>path==='context'?{...map,systems:[{id:vault,rotation_required:true}]}:{workflows:[{...plan,status:'waiting_unlock',plan:{dry_run:false,vaults:[{vault}]}}]});
  render(<AccessWorkflows browser={browser()} request={request} vaultSession={session} selectedVault={{origin:connection.origin,vaultId:vault}} vaultUnlocked/>);
  await screen.findByText('Vault access changed');
  fireEvent.click(screen.getByRole('button',{name:'Refresh workflows'}));
  await waitFor(()=>expect(screen.getByRole('button',{name:'Refresh workflows'})).not.toBeDisabled());
  expect(rotateConnectedVault).toHaveBeenCalledOnce();
  fireEvent.click(screen.getByRole('button',{name:'Rotate connected vault key'}));
  await waitFor(()=>expect(rotateConnectedVault).toHaveBeenCalledTimes(2));
});
