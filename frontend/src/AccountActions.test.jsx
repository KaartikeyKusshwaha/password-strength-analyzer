import {expect,it,vi} from 'vitest';
import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import {webcrypto} from 'node:crypto';
import AccountActions from './AccountActions';
import {sealAction,openAction} from './action-crypto';
const entry={id:'fixture-entry',type:'login',title:'Fixture account',origin:'https://example.test',username:'fixture',password:'fixture-password-never-real'};
it('requires an explicit selection/approval and sends only the encrypted plan and scope metadata',async()=>{
  vi.stubGlobal('crypto',webcrypto);const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  const fetcher=vi.fn(async(url,options)=>({ok:true,json:async()=>options.body?{id:'queued',status:'queued'}:{actions:[]}}));vi.stubGlobal('fetch',fetcher);
  render(<AccountActions entries={[entry]} vaultId={'b'.repeat(24)} actor={'c'.repeat(24)} kind="personal" seal={manifest=>sealAction(manifest,key)}/>);
  expect(screen.getByRole('button',{name:'Approve selected account preparation'})).toBeDisabled();
  fireEvent.click(screen.getByLabelText(/Fixture account ·/));fireEvent.click(screen.getByLabelText(/I approve preparation/));
  fireEvent.click(screen.getByRole('button',{name:'Approve selected account preparation'}));
  await screen.findByRole('status');
  const body=JSON.parse(fetcher.mock.calls.find(([,options])=>options.body)[1].body);
  expect(JSON.stringify(body)).not.toContain(entry.origin);expect(JSON.stringify(body)).not.toContain(entry.username);expect(JSON.stringify(body)).not.toContain(entry.password);
  expect((await openAction(body.envelope,key,{...body,user:'c'.repeat(24)})).items).toEqual([{entry_id:entry.id,origin:entry.origin}]);
});
it('allows a staged password to be recovered without silently replacing the old credential',async()=>{
  vi.stubGlobal('fetch',vi.fn(async()=>({ok:true,json:async()=>({actions:[]})})));
  const onSave=vi.fn(async()=>{}),staged={...entry,pending_change:{action_id:'a'.repeat(24),password:'staged-fixture-new-password',created_at:new Date().toISOString()}};
  render(<AccountActions entries={[staged]} vaultId={'b'.repeat(24)} actor={'c'.repeat(24)} kind="personal" seal={vi.fn()} canPrepare={false} onSave={onSave}/>);
  expect(screen.queryByText('staged-fixture-new-password')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'Show staged password for 10 seconds'}));expect(screen.getByText('staged-fixture-new-password')).toBeInTheDocument();expect(onSave).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button',{name:'Website accepted it — use staged password'}));
  await waitFor(()=>expect(onSave).toHaveBeenCalledWith([expect.objectContaining({password:'staged-fixture-new-password',change_receipt:expect.anything()})]));
});
