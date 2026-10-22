import React from 'react';
import {expect,it,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import AccountDiscovery from '../../companion/extension/AccountDiscovery';
const origin='https://app.example.test',client='a'.repeat(24),consent={id:'c'.repeat(24),domain:'app.example.test',origin,account_label:'Client account',client_id:client};
function fixture(sites=[]){
  const saved={discoveryConnection:{kind:'discovery'},discoverySites:sites};
  const browser={storage:{local:{get:vi.fn(async()=>({...saved})),set:vi.fn(async data=>Object.assign(saved,data)),remove:vi.fn(async key=>{delete saved[key];})}},runtime:{sendMessage:vi.fn(async()=>({ok:true,connection:true,sites:saved.discoverySites,context:{clients:[{id:client,name:'Client Orchard'}]}}))},permissions:{request:vi.fn(async()=>true)}};
  render(<AccountDiscovery browser={browser} active={{origin}}/>);fireEvent.click(screen.getByText('Account discovery · opt in per site'));return {browser,saved};
}

it('requires an explicit client, nickname and exact-site permission to enable collection',async()=>{
  const {browser}=fixture();
  fireEvent.change(await screen.findByLabelText('Client for this site'),{target:{value:client}});
  fireEvent.change(screen.getByLabelText('Account nickname'),{target:{value:'Client account'}});
  fireEvent.click(screen.getByRole('button',{name:'Enable discovery on this site'}));
  await waitFor(()=>expect(browser.runtime.sendMessage).toHaveBeenCalledWith({type:'discovery-enable',origin,client,label:'Client account'}));
  expect(browser.permissions.request).toHaveBeenCalledWith({origins:[origin+'/*']});
});

it('does not enable anything when exact-site permission is declined',async()=>{
  const {browser}=fixture();browser.permissions.request.mockResolvedValue(false);
  fireEvent.change(await screen.findByLabelText('Client for this site'),{target:{value:client}});
  fireEvent.change(screen.getByLabelText('Account nickname'),{target:{value:'Nickname'}});
  fireEvent.click(screen.getByRole('button',{name:'Enable discovery on this site'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('declined');
  expect(browser.runtime.sendMessage.mock.calls.some(([message])=>message.type==='discovery-enable')).toBe(false);
});

it('shows collection stopped locally even if the service-side disable fails',async()=>{
  const {browser,saved}=fixture([consent]);
  const button=await screen.findByRole('button',{name:'Stop recording app.example.test'});
  browser.runtime.sendMessage.mockImplementation(async message=>{if(message.type==='discovery-disable'){saved.discoverySites=[];return {ok:false,error:'Server unavailable; collection stopped locally.'};}return {ok:true};});
  fireEvent.click(button);
  expect(await screen.findByRole('alert')).toHaveTextContent('stopped locally');
  await waitFor(()=>expect(screen.queryByRole('button',{name:'Stop recording app.example.test'})).not.toBeInTheDocument());
});
