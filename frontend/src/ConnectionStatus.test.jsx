import {beforeEach,expect,it,vi} from 'vitest';
import {act,fireEvent,render,screen} from '@testing-library/react';
import ConnectionStatus from './ConnectionStatus';
import {api,setCsrf} from './api';
import {reportConnection} from './connection-state';
beforeEach(()=>{reportConnection('unknown');setCsrf('');});
it('shows a real network failure and recovers through a read-only retry without replaying the failed write',async()=>{
  const fetcher=vi.fn().mockRejectedValueOnce(new TypeError('private native error')).mockResolvedValueOnce({ok:true,status:200,json:async()=>({setup_required:false})});
  vi.stubGlobal('fetch',fetcher);render(<ConnectionStatus/>);
  expect(screen.getByRole('status')).toHaveTextContent('Checking backend');
  await act(async()=>{await expect(api('/vault',{envelope:'ciphertext-fixture'})).rejects.toThrow('Cannot reach SentinelOps');});
  expect(screen.getByRole('status')).toHaveTextContent('Backend unavailable');
  fireEvent.click(screen.getByRole('button',{name:'Retry connection'}));
  await screen.findByText('Backend reachable');
  expect(fetcher).toHaveBeenCalledTimes(2);expect(fetcher.mock.calls[1][0]).toBe('/api/status');expect(fetcher.mock.calls[1][1].method).toBe('GET');
  expect(screen.queryByRole('button',{name:'Retry connection'})).not.toBeInTheDocument();
});
it('reports server and invalid-response failures separately from expected authorization errors',async()=>{
  const fetcher=vi.fn().mockResolvedValueOnce({ok:false,status:503,json:async()=>({detail:'Unavailable'})}).mockResolvedValueOnce({ok:false,status:401,json:async()=>({detail:'Sign in required'})}).mockResolvedValueOnce({ok:true,status:200,json:async()=>{throw new SyntaxError('private response body');}});
  vi.stubGlobal('fetch',fetcher);render(<ConnectionStatus/>);
  await act(async()=>{await expect(api('/status')).rejects.toThrow('Unavailable');});expect(screen.getByRole('status')).toHaveTextContent('Backend error');
  await act(async()=>{await expect(api('/me')).rejects.toMatchObject({status:401});});expect(screen.getByRole('status')).toHaveTextContent('Backend reachable');
  await act(async()=>{await expect(api('/status')).rejects.toThrow('SentinelOps returned an unexpected response.');});expect(screen.getByRole('status')).toHaveTextContent('Backend error');
});
it('preserves same-origin credentials and CSRF behavior',async()=>{
  const fetcher=vi.fn(async()=>({ok:true,status:200,json:async()=>({csrf:'fixture-csrf'})}));vi.stubGlobal('fetch',fetcher);
  await api('/me');await api('/assets',{name:'Fixture'});
  expect(fetcher.mock.calls[1][1]).toMatchObject({credentials:'same-origin',method:'POST',headers:{'X-CSRF-Token':'fixture-csrf'},body:'{"name":"Fixture"}'});
});
