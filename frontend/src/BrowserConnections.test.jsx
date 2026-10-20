import {beforeEach,expect,it,vi} from 'vitest';
import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import BrowserConnections from './BrowserConnections';
import {api} from './api';
vi.mock('./api',()=>({api:vi.fn()}));
const connection={id:'opaque-id',label:'Acceptance browser',kind:'personal',expires:2000000000,last_contact:null,reported_version:null};
beforeEach(()=>{vi.mocked(api).mockReset();});
it('distinguishes an issued token with no contact from a reported version and preserves the limits',async()=>{
  vi.mocked(api).mockResolvedValueOnce({download_version:'0.12.7',connections:[connection]}).mockResolvedValueOnce({download_version:'0.12.7',connections:[{...connection,last_contact:1792525289,reported_version:'0.12.6'}]});
  render(<BrowserConnections/>);
  await screen.findByText('No successful vault contact recorded yet.');
  expect(screen.getByText(/Version not reported/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'Refresh browser connections'}));
  await screen.findByText(/Client reports version 0.12.6/);
  expect(screen.getByText(/Differs from the downloadable build/)).toBeInTheDocument();
  expect(screen.getByText(/does not prove installation/)).toBeInTheDocument();
});
it('does not turn a failed refresh into a clean empty connection report',async()=>{
  vi.mocked(api).mockResolvedValueOnce({download_version:'0.12.7',connections:[connection]}).mockRejectedValueOnce(new Error('Service unavailable'));
  render(<BrowserConnections/>);await screen.findByText('Acceptance browser');
  fireEvent.click(screen.getByRole('button',{name:'Refresh browser connections'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('may be out of date');
  expect(screen.getByText('Acceptance browser')).toBeInTheDocument();
  expect(screen.queryByText(/No active browser tokens/)).not.toBeInTheDocument();
});
it('refreshes after connection creation or revocation without exposing the token',async()=>{
  vi.mocked(api).mockResolvedValueOnce({download_version:null,connections:[connection]}).mockResolvedValueOnce({download_version:'0.12.7',connections:[]});
  const {rerender}=render(<BrowserConnections refreshKey={0}/>);await screen.findByText('Acceptance browser');
  rerender(<BrowserConnections refreshKey={1}/>);
  await screen.findByText('No active browser tokens. Create a private connection below.');
  await waitFor(()=>expect(api).toHaveBeenCalledTimes(2));
  expect(api.mock.calls).toEqual([['/companions'],['/companions']]);
});
it('reviews an exact connection before disconnecting and keeps the other connection visible',async()=>{
  let revoked=false;
  const other={...connection,id:'other-opaque-id',label:'Other browser'};
  vi.mocked(api).mockImplementation(async(path,body)=>{
    if(body){revoked=true;return {ok:true};}
    return {download_version:'0.12.7',connections:revoked?[other]:[connection,other]};
  });
  render(<BrowserConnections/>);
  fireEvent.click(await screen.findByRole('button',{name:'Disconnect Acceptance browser',exact:true}));
  expect(api.mock.calls.some(([,body])=>body)).toBe(false);
  expect(screen.getByText(/cannot erase plaintext/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'Keep this connection'}));
  expect(screen.queryByRole('button',{name:'Confirm disconnect Acceptance browser'})).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'Disconnect Acceptance browser',exact:true}));
  fireEvent.click(screen.getByRole('button',{name:'Confirm disconnect Acceptance browser',exact:true}));
  expect(await screen.findByRole('status')).toHaveTextContent('Other browser connections and encrypted vault data are retained');
  expect(screen.queryByText('Acceptance browser',{selector:'strong'})).not.toBeInTheDocument();
  expect(screen.getByText('Other browser',{selector:'strong'})).toBeInTheDocument();
  expect(api).toHaveBeenCalledWith('/companions/opaque-id/revoke',{});
});
it('does not claim disconnection when the server rejects the action',async()=>{
  vi.mocked(api).mockImplementation(async(path,body)=>{if(body)throw new Error('Sign in required');return {download_version:'0.12.7',connections:[connection]};});
  render(<BrowserConnections/>);
  fireEvent.click(await screen.findByRole('button',{name:'Disconnect Acceptance browser',exact:true}));
  fireEvent.click(screen.getByRole('button',{name:'Confirm disconnect Acceptance browser',exact:true}));
  expect(await screen.findByRole('alert')).toHaveTextContent('Sign in required');
  expect(screen.getByText('Acceptance browser',{selector:'strong'})).toBeInTheDocument();
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
});
