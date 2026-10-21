import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen,waitFor} from '@testing-library/react';
import DevicePairing from '../../companion/extension/DevicePairing';
afterEach(()=>{cleanup();vi.unstubAllGlobals();});
const connection={kind:'security',origin:'https://service.example',token:'fixture'};
it('does not expand existing assessment-only access',()=>{
  render(<DevicePairing connection={connection} enabled={false} running={false} browser={{}} onConnected={vi.fn()}/>);
  expect(screen.getByText(/Existing assessment-only access cannot create/)).toBeInTheDocument();
  expect(screen.queryByLabelText('Helper pairing code')).not.toBeInTheDocument();
});
it('reviews the exact scope then reauthenticates without keeping account credentials',async()=>{
  const onConnected=vi.fn(),fetcher=vi.fn(async url=>({ok:true,json:async()=>url.endsWith('/details')?{label:'This Windows helper',allow_posture:true,allow_updates:false}:{id:'a'.repeat(24)}}));vi.stubGlobal('fetch',fetcher);
  render(<DevicePairing connection={connection} enabled running={false} browser={{}} onConnected={onConnected}/>);
  fireEvent.change(screen.getByLabelText('Helper pairing code'),{target:{value:'ABCD-2345'}});
  fireEvent.click(screen.getByRole('button',{name:'Review helper scope'}));
  const password=await screen.findByLabelText('Current SentinelOps account password');
  fireEvent.change(password,{target:{value:'testing-only-account-password'}});
  fireEvent.click(screen.getByRole('button',{name:'Approve this helper connection'}));
  await waitFor(()=>expect(onConnected).toHaveBeenCalled());
  expect(JSON.parse(fetcher.mock.calls[1][1].body)).toMatchObject({pairing_code:'ABCD2345',allow_posture:true,allow_updates:false,password:'testing-only-account-password'});
  expect(screen.queryByLabelText('Current SentinelOps account password')).not.toBeInTheDocument();
  expect(screen.getByText(/Approved. Keep the helper open/)).toBeInTheDocument();
});
