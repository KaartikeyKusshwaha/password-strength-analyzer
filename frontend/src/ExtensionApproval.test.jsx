import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen} from '@testing-library/react';
import ExtensionApproval from './ExtensionApproval';
const request={id:'a'.repeat(24),origin:'chrome-extension://'+'a'.repeat(32),code:'123456',status:'pending'};
it('presents workflow permission independently of vault and scanner grants',async()=>{
  const fetcher=vi.fn(async url=>({ok:true,json:async()=>url.endsWith('/team-vaults')||url.endsWith('/vaults')?{vaults:[]}:url.endsWith('/approve')?{approved:true}:{...request,scope:'access',workspace_id:'w'}}));vi.stubGlobal('fetch',fetcher);
  render(<ExtensionApproval identifier={request.id} onClose={()=>{}}/>);
  const approve=await screen.findByRole('button',{name:'Approve connection'});
  expect(screen.queryByLabelText('Vault to connect')).not.toBeInTheDocument();
  expect(screen.getByText(/eight hours/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(approve);
  await screen.findByRole('status');
  expect(JSON.parse(fetcher.mock.calls.find(([url])=>url.endsWith('/approve'))[1].body)).toEqual({workspace_id:'w',device_pairing:false,confirmed_code:'123456'});
});
afterEach(()=>{cleanup();vi.unstubAllGlobals();});
it('requires explicit code confirmation and offers only initialized browser-enabled vaults',async()=>{
  const fetcher=vi.fn(async url=>({ok:true,json:async()=>url.endsWith('/team-vaults')?{vaults:[]}:url.endsWith('/vaults')?{vaults:[{id:'v',name:'Work',initialized:true,browser_enabled:true},{id:'hidden',name:'Uninitialized',initialized:false,browser_enabled:true}]}:url.endsWith('/approve')?{approved:true}:request}));vi.stubGlobal('fetch',fetcher);
  render(<ExtensionApproval identifier={request.id} onClose={()=>{}}/>);
  const approve=await screen.findByRole('button',{name:'Approve connection'});
  expect(approve).toBeDisabled();expect(screen.queryByText('Uninitialized')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(approve);
  expect(await screen.findByRole('status')).toHaveTextContent('Return to the extension');
  const call=fetcher.mock.calls.find(([url])=>url.endsWith('/approve'));
  expect(JSON.parse(call[1].body)).toEqual({vault_id:'v',vault_kind:'personal',confirmed_code:'123456'});
});

it('connects accepted shared vaults without manual tokens and re-confirms a changed selection',async()=>{
  const fetcher=vi.fn(async url=>({ok:true,json:async()=>url.endsWith('/team-vaults')?{vaults:[{id:'s',name:'Client accounts',accepted:true,browser_enabled:true,role:'viewer'},{id:'pending',name:'Pending',accepted:false,browser_enabled:true},{id:'disabled',name:'Disabled',accepted:true,browser_enabled:false}]}:url.endsWith('/vaults')?{vaults:[{id:'p',name:'Personal',initialized:true,browser_enabled:true}]}:url.endsWith('/approve')?{approved:true}:request}));
  vi.stubGlobal('fetch',fetcher);
  render(<ExtensionApproval identifier={request.id} onClose={()=>{}}/>);
  const approve=await screen.findByRole('button',{name:'Approve connection'});
  expect(screen.queryByRole('option',{name:/Pending|Disabled/})).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.change(screen.getByLabelText('Vault to connect'),{target:{value:'shared:s'}});
  expect(approve).toBeDisabled();expect(screen.getByText(/sharing passphrase and verify the owner fingerprint/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(approve);
  await screen.findByRole('status');
  expect(JSON.parse(fetcher.mock.calls.find(([url])=>url.endsWith('/approve'))[1].body)).toEqual({vault_id:'s',vault_kind:'shared',confirmed_code:'123456'});
});
