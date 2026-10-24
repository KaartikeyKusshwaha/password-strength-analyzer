import {useEffect,useRef,useState} from 'react';
import {api} from './api';

const roleLabel={removed:'Remove my vault access',viewer:'Keep view access',editor:'Keep edit access',admin:'Keep admin access'};
export default function OwnershipTransfer({team,me,directory,busy,onPropose,onAccept,onCancel}) {
  const [proposal,setProposal]=useState(null),[error,setError]=useState(''),[loading,setLoading]=useState(true);
  const generation=useRef(0);
  useEffect(()=>{
    const mark=++generation.current;let active=true;
    setProposal(null);
    if(me.role==='viewer' || busy){setLoading(false);return ()=>{generation.current++;};}
    setLoading(true);setError('');
    async function load(){try{
      const result=await api('/team-vaults/'+team.id+'/ownership');
      if(active && mark===generation.current){setProposal(result.proposal);setError('');}
    }catch(e){if(active && mark===generation.current){setProposal(null);setError(e.message);}}
    finally{if(active && mark===generation.current)setLoading(false);}}
    load();const timer=setInterval(load,8000);
    return ()=>{active=false;generation.current++;clearInterval(timer);};
  },[team.id,team.revision,team.epoch,me.role,busy]);
  if(me.role==='viewer')return null;
  const visible=proposal?.document?.vault_id===team.id?proposal:null;
  const owner=team.owner===me.id,document=visible?.document,pending=visible?.status==='pending';
  const eligible=directory.filter(person=>person.id!==team.owner && person.public && person.role!=='viewer' && team.grants.some(grant=>grant.user_id===person.id && grant.accepted));
  return <details className="spaced"><summary>Vault ownership and handoff</summary>
    <p>Ownership changes only after the current owner proposes a successor and that teammate accepts. Acceptance creates a new encryption key, revokes this vault’s browser connections and cancels its unfinished account-action plans. Existing decrypted copies cannot be erased.</p>
    {loading && <p role="status">Loading ownership proposal…</p>}
    {error && <p className="notice error" role="alert">{error}</p>}
    {visible && <div className="notice"><strong>Transfer {visible.status}</strong><p>Successor: {directory.find(person=>person.id===document.recipient)?.email || 'Selected teammate'}. Former owner’s access: {document.former_owner_role}. Proposal deadline: {new Date(document.expires_at*1000).toLocaleString()}.</p></div>}
    {owner && !pending && !loading && !error && <form className="operator-form" onSubmit={event=>{
      event.preventDefault();const form=event.currentTarget,fields=new FormData(form);
      const recipient=fields.get('next_owner'),role=fields.get('former_role');form.reset();onPropose(recipient,role);
    }}>
      <h4>Propose a new owner</h4><p className="fine">Choose a teammate who has accepted this vault. Their identity must match the signed grant. The proposal lasts 15 minutes; content, access or browser-policy changes require a fresh proposal.</p>
      <label>New vault owner<select name="next_owner" required disabled={busy || team.rotation_required}><option value="">Choose an accepted teammate</option>{eligible.map(person=><option key={person.id} value={person.id}>{person.email}</option>)}</select></label>
      <label>Your access after transfer<select name="former_role" required disabled={busy || team.rotation_required}><option value="">Choose your retained access</option>{Object.entries(roleLabel).map(([value,label])=><option key={value} value={value}>{label}</option>)}</select></label>
      {!eligible.length && <p>No eligible accepted teammate is available. Invite a teammate and have them accept first.</p>}
      <button className="button secondary" disabled={busy || team.rotation_required || !eligible.length}>Sign ownership proposal</button>
    </form>}
    {pending && document.recipient===me.id && <form className="operator-form spaced" onSubmit={event=>{event.preventDefault();event.currentTarget.reset();onAccept(proposal);}}>
      <h4>Accept ownership</h4><p>The former owner will have <strong>{document.former_owner_role==='removed'?'no vault access':document.former_owner_role+' access'}</strong>. Other member roles remain unchanged. Staged website passwords remain encrypted for reconciliation; cancelled plans are not proof that a website was unchanged.</p>
      <label className="check"><input type="checkbox" required/>I accept ownership, the listed member access and replacing this vault’s encryption key.</label>
      <button className="button" disabled={busy || loading}>Accept ownership and rotate vault key</button>
    </form>}
    {pending && (owner || document.recipient===me.id) && <button type="button" className="button secondary spaced" disabled={busy || loading} onClick={()=>onCancel(proposal)}>{owner?'Cancel ownership proposal':'Decline ownership transfer'}</button>}
    <p className="fine">Each member must verify the new owner fingerprint before reopening or pairing. Transferring a vault does not change workspace ownership or remove a teammate from the workspace.</p>
  </details>;
}
