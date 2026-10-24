import {expect,it,vi} from 'vitest';
import {securityRequest} from '../../companion/extension/security-client';
it('does not reuse a vault grant or request unrestricted workspace endpoints',async()=>{
  const fetcher=vi.fn();
  await expect(securityRequest({kind:'personal',origin:'https://service.example',token:'vault'},'/context',undefined,fetcher)).rejects.toThrow('separate security');
  await expect(securityRequest({kind:'security',origin:'https://service.example',token:'security'},'/../workspace',undefined,fetcher)).rejects.toThrow('separate security');
  expect(fetcher).not.toHaveBeenCalled();
});
it('uses a bearer grant without cookies or redirects and fails closed after revocation',async()=>{
  const connection={kind:'security',origin:'https://service.example',token:'fixture'};
  const fetcher=vi.fn(async()=>({ok:true,json:async()=>({workspace:'Example',devices:[]})}));
  expect(await securityRequest(connection,'/context',undefined,fetcher)).toMatchObject({devices:[]});
  expect(fetcher.mock.calls[0][1]).toMatchObject({credentials:'omit',redirect:'error',headers:{Authorization:'Bearer fixture'}});
  fetcher.mockResolvedValue({ok:false,status:401});
  await expect(securityRequest(connection,'/context',undefined,fetcher)).rejects.toThrow('expired');
});
