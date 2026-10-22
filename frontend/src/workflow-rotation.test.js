import {expect,it,vi} from 'vitest';
import {rotateConnectedVault} from '../../companion/extension/workflow-rotation';
import {rotateTeamVault} from './sharing-crypto';
vi.mock('./sharing-crypto',()=>({rotateTeamVault:vi.fn(async()=>({revision:1,payload:{ciphertext:'encrypted-test-fixture'},grants:[]}))}));
const workflow='a'.repeat(24),vault='b'.repeat(24),access={origin:'https://example.test',kind:'access',token:'a'.repeat(54)};
function session(){return {config:{origin:access.origin,vaultId:vault,token:'b'.repeat(54)},material:{kind:'shared',epoch:1,identity:{user:'owner'},trusted:'fingerprint'},external:vi.fn(async task=>task({active:()=>{},signal:new AbortController().signal}))};}
it('combines scoped capabilities only for the selected vault and encrypts locally',async()=>{
  const value=session(),request=vi.fn(async(_,path,body)=>body?{epoch:2}:{team:{id:vault,owner:'owner',epoch:1},directory:[]});
  await rotateConnectedVault(access,value,workflow,vault,request);
  expect(rotateTeamVault).toHaveBeenCalledWith({id:vault,owner:'owner',epoch:1},value.material.identity,'fingerprint',[]);
  expect(request.mock.calls[1][2]).toMatchObject({payload:{ciphertext:'encrypted-test-fixture'}});
  expect(request.mock.calls[0][4]).toMatchObject({vaultToken:value.config.token});
});
it('rejects wrong origins, locked vaults and changed epochs before uploading a rotation',async()=>{
  const request=vi.fn();
  await expect(rotateConnectedVault(access,{...session(),material:null},workflow,vault,request)).rejects.toThrow('Select and unlock');
  await expect(rotateConnectedVault({...access,origin:'https://other.test'},session(),workflow,vault,request)).rejects.toThrow('Select and unlock');
  expect(request).not.toHaveBeenCalled();
  request.mockResolvedValue({team:{id:vault,owner:'owner',epoch:2}});
  await expect(rotateConnectedVault(access,session(),workflow,vault,request)).rejects.toThrow('Vault access changed');
  expect(request).toHaveBeenCalledTimes(1);
});
