import {expect,it,vi,beforeEach} from 'vitest';
import {loadConnectedOwnership,changeConnectedOwnership} from '../../companion/extension/ownership-operator';
import {verifyTeam,ownershipStateDigest,prepareOwnershipProposal,acceptOwnershipTransfer} from './sharing-crypto';
vi.mock('./sharing-crypto',()=>({canonical:JSON.stringify,verifyTeam:vi.fn(async()=>({})),ownershipStateDigest:vi.fn(async team=>String(team.revision)),prepareOwnershipProposal:vi.fn(async()=>({signed:'proposal'})),acceptOwnershipTransfer:vi.fn(async()=>({encrypted:'next-epoch'}))}));
const vault='a'.repeat(24),id='b'.repeat(24),access={origin:'https://service.example.test',kind:'access',token:'a'.repeat(54)};
const context={team:{id:vault,epoch:1,revision:1},directory:[{id:'next'}],proposal:{id,status:'pending',document:{id}}};
function session(){return {config:{origin:access.origin,vaultId:vault,token:'v'.repeat(54)},material:{kind:'shared',epoch:1,identity:{user:'owner'},trusted:'fp'},entries:[],revision:1,pending:new Set(),lock:vi.fn(),external:vi.fn(async work=>work({active:()=>{},signal:new AbortController().signal}))};}
beforeEach(()=>vi.clearAllMocks());
it('rejects locked, wrong-origin and concurrently active vaults without network access',async()=>{
 const request=vi.fn(),value=session();await expect(loadConnectedOwnership(access,{...value,material:null},request)).rejects.toThrow('Select and unlock');await expect(loadConnectedOwnership({...access,origin:'https://other.test'},value,request)).rejects.toThrow('Select and unlock');value.pending.add('ongoing');await expect(loadConnectedOwnership(access,value,request)).rejects.toThrow('Wait for');expect(request).not.toHaveBeenCalled();
});
it('rejects stale server snapshots and local changes before uploading signatures',async()=>{
 const value=session(),request=vi.fn(async()=>({...context,team:{...context.team,revision:2}}));await expect(changeConnectedOwnership(access,value,context,'propose','next','removed',request)).rejects.toThrow('Vault access changed');expect(prepareOwnershipProposal).not.toHaveBeenCalled();
 request.mockImplementation(async()=>context);prepareOwnershipProposal.mockImplementationOnce(async()=>{value.entries=[];return {signed:'proposal'};});await expect(changeConnectedOwnership(access,value,context,'propose','next','removed',request)).rejects.toThrow('changed locally');expect(request.mock.calls.filter(call=>call[2])).toHaveLength(0);
});
it('locks on uncertain acceptance and never reports it as a verified transfer',async()=>{
 const value=session(),request=vi.fn(async(_,path,body)=>{if(body)throw new Error('connection dropped');return context;});const result=changeConnectedOwnership(access,value,context,'accept',null,'removed',request);await expect(result).rejects.toMatchObject({ownershipAttempted:true,message:'connection dropped'});expect(value.lock).toHaveBeenCalledTimes(1);
});
it('cancels only the exact pending proposal without preparing a new key',async()=>{
 const value=session(),request=vi.fn(async(_,path,body)=>body?{status:'cancelled'}:context);await changeConnectedOwnership(access,value,context,'cancel',null,'removed',request);expect(request.mock.calls.at(-1)[1]).toBe('vaults/'+vault+'/ownership/'+id+'/cancel');expect(acceptOwnershipTransfer).not.toHaveBeenCalled();expect(value.lock).not.toHaveBeenCalled();
});

it('rejects a changed proposal document even when the server reuses its ID',async()=>{
 const value=session(),request=vi.fn(async()=>({...context,proposal:{...context.proposal,document:{id,former_owner_role:'admin'}}}));await expect(changeConnectedOwnership(access,value,context,'accept',null,'removed',request)).rejects.toThrow('proposal changed');expect(acceptOwnershipTransfer).not.toHaveBeenCalled();expect(request).toHaveBeenCalledTimes(1);
});
