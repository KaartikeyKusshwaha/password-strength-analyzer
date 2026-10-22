import React from 'react';
import {beforeEach,expect,it,vi} from 'vitest';
import {fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import ClientAccess from './ClientAccess';
import {api} from './api';
vi.mock('./api',()=>({api:vi.fn()}));
const fixture=()=>({clients:[{id:'c1',name:'Orchard'},{id:'c2',name:'Cedar'}],systems:[{client:'c1',id:'v1',name:'Orchard accounts',rotation_required:1},{client:'c2',id:'v2',name:'Cedar accounts',rotation_required:0}],grants:[{client:'c1',person_id:'p1',email:'owner@example.test',system_id:'v1',role:'owner',state:'accepted'},{client:'c2',person_id:'p2',email:'invite@example.test',system_id:'v2',role:'viewer',state:'invited'}],available_vaults:[{id:'v1',name:'Orchard accounts'}],coverage:'Vault memberships only; not proof of website access.'});
beforeEach(()=>{api.mockReset();api.mockImplementation(async path=>path==='/clients/access-map'?fixture():{ok:true});});
it('distinguishes invitations from access and surfaces incomplete rotation',async()=>{
  render(<ClientAccess/>);
  expect(await screen.findByText('owner@example.test',{selector:'td'})).toBeInTheDocument();
  expect(screen.getByText('Invitation pending · not accepted access')).toBeInTheDocument();
  expect(screen.getByText(/Key rotation required: Orchard/)).toBeInTheDocument();
  expect(screen.getByText('Vault memberships only; not proof of website access.')).toBeInTheDocument();
});
it('answers client and person questions by filtering current memberships',async()=>{
  render(<ClientAccess/>);await screen.findByText('owner@example.test',{selector:'td'});
  fireEvent.change(screen.getByLabelText('Client',{exact:true}),{target:{value:'c2'}});
  const table=screen.getByRole('table');
  expect(within(table).queryByText('owner@example.test')).not.toBeInTheDocument();
  expect(within(table).getByText('invite@example.test')).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Person',{exact:true}),{target:{value:'p1'}});
  expect(screen.getByText(/No matching memberships/)).toBeInTheDocument();
});
it('creates client metadata and explicitly links a selected existing vault',async()=>{
  render(<ClientAccess/>);await screen.findByText('owner@example.test',{selector:'td'});
  fireEvent.change(screen.getByLabelText('Client name'),{target:{value:'New client'}});
  fireEvent.click(screen.getByRole('button',{name:'Create client record'}));
  await waitFor(()=>expect(api).toHaveBeenCalledWith('/clients',{name:'New client'}));
  await waitFor(()=>expect(screen.getByRole('button',{name:'Link shared vault'})).toBeEnabled());
  fireEvent.click(screen.getByRole('button',{name:'Link shared vault'}));
  await waitFor(()=>expect(api).toHaveBeenCalledWith('/clients/c1/vaults',{vault_id:'v1'}));
});
it('reports authorization errors without displaying a fake empty all-clear map',async()=>{
  api.mockRejectedValue(new Error('Workspace owner access required'));
  render(<ClientAccess/>);
  expect(await screen.findByRole('alert')).toHaveTextContent('Workspace owner access required');
  expect(screen.queryByRole('table')).not.toBeInTheDocument();
  expect(screen.queryByText(/No matching memberships/)).not.toBeInTheDocument();
});
