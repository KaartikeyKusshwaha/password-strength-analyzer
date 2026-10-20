import {expect,it,vi} from 'vitest';
import {fireEvent,render,screen,within} from '@testing-library/react';
import Companions from './Companions';

it('pairs an accepted shared vault with explicit scope and never offers pending or disabled vaults',async()=>{
  const identifier='a'.repeat(24);
  const fetcher=vi.fn(async(url,options)=>({ok:true,json:async()=>url==='/api/vaults'?{vaults:[]}:url==='/api/team-vaults'?{vaults:[{id:identifier,name:'Client accounts',accepted:1,browser_enabled:true,role:'viewer'},{id:'pending',name:'Pending vault',accepted:0,browser_enabled:true},{id:'disabled',name:'Disabled vault',accepted:1,browser_enabled:false}]}:{kind:'shared',vault_name:'Client accounts',token:'public-fixture-token-not-real',origin:'http://127.0.0.1:8110',expires_days:30}}));
  const original=fetcher.getMockImplementation();
  fetcher.mockImplementation((url,options)=>url==='/api/companions' && !options?.body?Promise.resolve({ok:true,json:async()=>({connections:[],download_version:'0.12.7'})}):original(url,options));
  vi.stubGlobal('fetch',fetcher);
  render(<Companions assets={[]} devices={[]} refresh={vi.fn()} canWrite={false} go={vi.fn()}/>);
  await screen.findByLabelText('Connection type');fireEvent.click(screen.getByText('Create a private connection'));
  fireEvent.change(screen.getByLabelText('Connection type'),{target:{value:'shared'}});
  await screen.findByRole('option',{name:'Client accounts · viewer'});
  expect(screen.queryByRole('option',{name:/Pending vault|Disabled vault/})).not.toBeInTheDocument();
  const form=screen.getByLabelText('Connection name').closest('form');
  fireEvent.change(within(form).getByLabelText('Connection name'),{target:{value:'Work browser'}});
  fireEvent.change(within(form).getByLabelText('Current app sign-in password'),{target:{value:'fixture-app-password-for-reauth-only'}});
  fireEvent.click(within(form).getByRole('button',{name:'Create scoped token'}));
  await screen.findByText('One-time display: pairing token');
  const request=fetcher.mock.calls.find(([url,options])=>url==='/api/companions' && options.body);
  expect(JSON.parse(request[1].body)).toMatchObject({kind:'shared',vault_id:identifier,label:'Work browser'});
  expect(screen.getByText(/one shared vault plus your encrypted sharing identity/)).toBeInTheDocument();
});
