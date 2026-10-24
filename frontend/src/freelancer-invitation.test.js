import {it,expect,vi,beforeEach} from 'vitest';
import {signFreelancerVault} from '../../companion/extension/freelancer-invitation';
import {verifyTeam,ownershipStateDigest} from './sharing-crypto';
vi.mock('./sharing-crypto',()=>({canonical:JSON.stringify,verifyTeam:vi.fn(async()=>({})),ownershipStateDigest:vi.fn(async()=> 'digest')}));
const vault='a'.repeat(24),person='b'.repeat(24),id='c'.repeat(24),connection={origin:'https://service.example.test'};
const draft={id,status:'pending',deadline:Date.now()/1000+900,plan_digest:'d'.repeat(64),plan:{person,role:'editor',recipient_fingerprint:'fp',vaults:[{vault,state_digest:'digest'}]}};
function setup(){const invite=vi.fn(async()=>({wrapped_key:'ciphertext',signature:'signed'})),session={config:{origin:connection.origin,vaultId:vault,token:'t'.repeat(54)},material:{kind:'shared',epoch:1,identity:{user:'owner'},trusted:'ownerfp',handle:{invite}},revision:1,entries:[],pending:new Set(),external:vi.fn(async work=>work({active:()=>{},signal:new AbortController().signal}))};const context={draft,team:{id:vault,epoch:1,revision:1,owner:'owner'},recipient:{id:person,fingerprint:'fp',public:{}}};return {session,context,invite,request:vi.fn(async()=>context)};}
beforeEach(()=>vi.clearAllMocks());
it('signs only after checking both the draft and current encrypted vault locally',async()=>{
 const {session,context,invite,request}=setup();const value=await signFreelancerVault(connection,session,draft,request);expect(invite).toHaveBeenCalledWith(context.recipient,'editor');expect(value).toEqual({vault_id:vault,token:'t'.repeat(54),grant:{wrapped_key:'ciphertext',signature:'signed'}});expect(request).toHaveBeenCalledTimes(1);expect(request.mock.calls[0][1]).toBe('invitations/'+id+'/vaults/'+vault);expect(request.mock.calls[0][4]).toMatchObject({vaultToken:'t'.repeat(54)});
});
it('rejects wrong selected vaults, expired drafts and concurrent actions before network access',async()=>{
 const {session,request}=setup();await expect(signFreelancerVault(connection,{...session,config:{...session.config,vaultId:'f'.repeat(24)}},draft,request)).rejects.toThrow('Select and unlock');await expect(signFreelancerVault(connection,session,{...draft,deadline:1},request)).rejects.toThrow('Select and unlock');session.pending.add('other');await expect(signFreelancerVault(connection,session,draft,request)).rejects.toThrow('Wait');expect(request).not.toHaveBeenCalled();
});
it('rejects changed recipient or vault snapshots before signing',async()=>{
 const {session,context,invite,request}=setup();request.mockResolvedValue({...context,recipient:{...context.recipient,fingerprint:'changed'}});await expect(signFreelancerVault(connection,session,draft,request)).rejects.toThrow('scope or identity');expect(invite).not.toHaveBeenCalled();request.mockResolvedValue(context);ownershipStateDigest.mockResolvedValueOnce('changed');await expect(signFreelancerVault(connection,session,draft,request)).rejects.toThrow('membership changed');expect(invite).not.toHaveBeenCalled();
});
it('drops a signature result when the vault changes locally during encryption',async()=>{
 const {session,invite,request}=setup();invite.mockImplementation(async()=>{session.entries=[];return {signature:'signed'};});await expect(signFreelancerVault(connection,session,draft,request)).rejects.toThrow('changed locally');
});
