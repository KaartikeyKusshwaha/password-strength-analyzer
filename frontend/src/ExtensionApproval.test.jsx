import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen} from '@testing-library/react';
import ExtensionApproval from './ExtensionApproval';
const request={id:'a'.repeat(24),origin:'chrome-extension://'+'a'.repeat(32),code:'123456',status:'pending'};
afterEach(()=>{cleanup();vi.unstubAllGlobals();});
it('requires explicit code confirmation and offers only initialized browser-enabled vaults',async()=>{
  const fetcher=vi.fn(async url=>({ok:true,json:async()=>url.endsWith('/vaults')?{vaults:[{id:'v',name:'Work',initialized:true,browser_enabled:true},{id:'hidden',name:'Uninitialized',initialized:false,browser_enabled:true}]}:url.endsWith('/approve')?{approved:true}:request}));vi.stubGlobal('fetch',fetcher);
  render(<ExtensionApproval identifier={request.id} onClose={()=>{}}/>);
  const approve=await screen.findByRole('button',{name:'Approve connection'});
  expect(approve).toBeDisabled();expect(screen.queryByText('Uninitialized')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(approve);
  expect(await screen.findByRole('status')).toHaveTextContent('Return to the extension');
  const call=fetcher.mock.calls.find(([url])=>url.endsWith('/approve'));
  expect(JSON.parse(call[1].body)).toEqual({vault_id:'v',confirmed_code:'123456'});
});
