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
