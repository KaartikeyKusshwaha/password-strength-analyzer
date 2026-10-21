import {expect,it,vi} from 'vitest';
import {websiteScope,checkWebsite} from '../../companion/extension/site-check';

it('checks only the root origin without website cookies or redirects',async()=>{
  const scope=websiteScope('https://example.com/private?token=secret#account');
  const fetcher=vi.fn(async()=>({status:200,headers:new Headers({'strict-transport-security':'max-age=31536000','content-security-policy':"default-src 'self'",'x-content-type-options':'nosniff'})}));
  const result=await checkWebsite(scope,fetcher);
  expect(result.actions).toEqual([]);
  expect(fetcher.mock.calls[0][0]).toBe('https://example.com/');
  expect(fetcher.mock.calls[0][1]).toMatchObject({method:'HEAD',credentials:'omit',redirect:'error',referrerPolicy:'no-referrer'});
  expect(JSON.stringify(result)).not.toContain('secret');
});
it('does not send an HTTP request or turn a failed check into a safety claim',async()=>{
  const fetcher=vi.fn();
  expect((await checkWebsite(websiteScope('http://example.com/login'),fetcher)).actions[0].id).toBe('https');
  expect(fetcher).not.toHaveBeenCalled();
  await expect(checkWebsite(websiteScope('https://example.com'),async()=>{throw new TypeError('failed');})).rejects.toThrow('No safety verdict');
});
it.each(['http://127.0.0.1','https://192.168.1.1','https://[::1]','https://localhost','https://device.local','https://example.com:8443','https://name:password@example.com'])('rejects device/internal/nonstandard targets: %s',value=>{
  expect(()=>websiteScope(value)).toThrow();
});
it('reports limited header observations without claiming a fix',async()=>{
  const result=await checkWebsite(websiteScope('https://example.com'),async()=>({status:403,headers:new Headers()}));
  expect(result.actions).toHaveLength(3);expect(result.status).toBe(403);
  expect(result.coverage).toContain('No redirects');
});
