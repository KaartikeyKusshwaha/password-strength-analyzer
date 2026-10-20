import {useCallback,useEffect,useRef,useState} from 'react';
import {api} from './api';
import {canonical,createSharingIdentity,unlockSharingIdentity,prepareSharingPassphraseChange,createTeamVault,verifyTeam,openTeamVault,rotateTeamVault,ownershipStateDigest,prepareOwnershipProposal,acceptOwnershipTransfer} from './sharing-crypto';
import {validOrigin,parseOtpAuth,generateTotp} from './vault-crypto';
import {generatePassword} from './lab';
import AccountActions from './AccountActions';
import AccountReview from './AccountReview';
import {isArchived,trackChanges} from './entry-history';
import SharingPassphraseChange from './SharingPassphraseChange';
import VaultActivity from './VaultActivity';
import OwnershipTransfer from './OwnershipTransfer';

function Secret({entry}) {
  const [value,setValue]=useState('');
  useEffect(()=>{setValue('');return ()=>setValue('');},[entry]);
  useEffect(()=>{if(!value)return;const timer=setTimeout(()=>setValue(''),10000);return ()=>clearTimeout(timer);},[value]);
  return <><span className="mono">{value || '••••••••'}</span><button className="button secondary" onClick={async()=>{try{setValue(value?'':entry.type==='totp'?await generateTotp(entry):entry.password);}catch{setValue('Code unavailable');}}}>{value?'Hide':entry.type==='totp'?'Show code for 10 seconds':'Reveal for 10 seconds'}</button></>;
}
function BrowserPolicy({value={},busy,onSave}) {
  return <details className="spaced"><summary>Shared vault browser permissions</summary><form className="operator-form" onSubmit={event=>{event.preventDefault();const fields=new FormData(event.currentTarget);onSave({browser_enabled:fields.has('enabled'),browser_save:fields.has('save'),browser_fill:fields.has('fill'),lock_seconds:Number(fields.get('timeout')),origins:fields.get('origins').split(',').map(v=>v.trim()).filter(Boolean)});}}>
    <label className="check"><input name="enabled" type="checkbox" defaultChecked={value.browser_enabled!==false}/>Allow browser connections</label>
    <label className="check"><input name="save" type="checkbox" defaultChecked={value.browser_save!==false}/>Allow members with edit access to save logins</label>
    <label className="check"><input name="fill" type="checkbox" defaultChecked={value.browser_fill!==false}/>Allow selected login fills and code reveals</label>
    <label>Companion lock timeout<select name="timeout" defaultValue={value.lock_seconds || 180}><option value={30}>30 seconds</option><option value={60}>1 minute</option><option value={180}>3 minutes</option></select></label>
    <label>Exact HTTPS website origins, comma separated<textarea name="origins" defaultValue={value.origins?.join(', ') || ''} rows={2}/></label><p className="fine">Leave blank for any exact HTTPS origin. Turning off browser access revokes all connections to this vault. Existing local copies cannot be erased. Website scopes constrain login saving/filling; authenticator entries have no website origin.</p><button className="button" disabled={busy}>Save shared browser policy</button>
  </form></details>;
}
export default function TeamVaults({me}) {
  const [record,setRecord]=useState(undefined),[unlocked,setUnlocked]=useState(false),[list,setList]=useState([]),[directory,setDirectory]=useState([]),[team,setTeam]=useState(null),[entries,setEntries]=useState(null),[busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState(''),[recipient,setRecipient]=useState(''),[entryType,setEntryType]=useState('login');
  const identity=useRef(null),handle=useRef(null),generation=useRef(0),trusted=useRef(''),timer=useRef(null);
  const lock=useCallback(()=>{generation.current++;handle.current?.close();handle.current=null;identity.current=null;trusted.current='';setUnlocked(false);setEntries(null);setTeam(null);clearTimeout(timer.current);},[]);
  const load=useCallback(async()=>{const [own,teams,members]=await Promise.all([api('/sharing/identity'),api('/team-vaults'),api('/sharing/directory')]);setRecord(own.identity);setList(teams.vaults);setDirectory(members.members);},[]);
  useEffect(()=>{const hidden=()=>{if(document.hidden)lock();};document.addEventListener('visibilitychange',hidden);load().catch(e=>setError(e.message));return ()=>{document.removeEventListener('visibilitychange',hidden);generation.current++;handle.current?.close();identity.current=null;clearTimeout(timer.current);};},[load,lock]);
  useEffect(()=>{
    if(!unlocked)return;
    const schedule=()=>{clearTimeout(timer.current);timer.current=setTimeout(lock,180000);},hidden=()=>{if(document.hidden)lock();};
    schedule();document.addEventListener('pointerdown',schedule);document.addEventListener('keydown',schedule);document.addEventListener('visibilitychange',hidden);
    return ()=>{clearTimeout(timer.current);document.removeEventListener('pointerdown',schedule);document.removeEventListener('keydown',schedule);document.removeEventListener('visibilitychange',hidden);};
  },[unlocked,lock]);
  useEffect(()=>{
    if(!team || busy)return;
    let active=true;
    const poll=setInterval(async()=>{try{const fresh=await api('/team-vaults/'+team.id);if(active && (fresh.revision!==team.revision || fresh.epoch!==team.epoch || fresh.rotation_required!==team.rotation_required || JSON.stringify(fresh.grants)!==JSON.stringify(team.grants))){generation.current++;handle.current?.close();handle.current=null;setEntries(null);setTeam(fresh);setNotice('Vault access or contents changed. Verify and open its current version again.');}}catch(e){if(active){lock();setError(e.message);}}},8000);
    return ()=>{active=false;clearInterval(poll);};
  },[team,busy,lock]);
  useEffect(()=>{
    if(!unlocked || busy || !record)return;
    let active=true;const mark=generation.current,who=identity.current;
    const poll=setInterval(async()=>{try{
      const fresh=await api('/sharing/identity');
      if(active && mark===generation.current && who===identity.current && canonical(fresh.identity)!==canonical(record)){
        lock();setRecord(fresh.identity);setNotice('Sharing protection changed in another session. Unlock its current version again.');
      }
    }catch(e){if(active && mark===generation.current){lock();setError(e.message);}}},8000);
    return ()=>{active=false;clearInterval(poll);};
  },[unlocked,busy,record,lock]);
  async function run(action) {setBusy(true);setError('');setNotice('');try{await action();}catch(e){setError(e.message);}finally{setBusy(false);}}
  async function choose(id) {
    const mark=++generation.current;handle.current?.close();handle.current=null;trusted.current='';setEntries(null);setTeam(null);
    const value=await api('/team-vaults/'+id);if(mark===generation.current)setTeam(value);
  }
  async function open(fingerprint) {
    const mark=generation.current, who=identity.current;const latest=await api('/team-vaults/'+team.id);
    const trust=latest.owner===who.user?who.fingerprint:fingerprint.trim().toLowerCase();
    await verifyTeam(latest,who,trust);
    if(mark!==generation.current)return;
    if(!latest.accepted){await api('/team-vaults/'+team.id+'/accept',{});if(mark!==generation.current)return;await load();await choose(team.id);setNotice('Invitation accepted. Verify and open the vault to read its encrypted contents.');return;}
    const opened=await openTeamVault(latest,who,trust);
    if(mark!==generation.current){opened.handle.close();return;}
    handle.current?.close();handle.current=opened.handle;trusted.current=trust;setTeam(latest);setEntries(opened.entries);
  }
  async function save(next) {
    const mark=generation.current,current=handle.current;if(!current)throw new Error('Unlock the shared vault first.');
    next=trackChanges(entries,next);const payload=await current.encrypt(next);if(mark!==generation.current)throw new Error('Shared vault locked; changes were not submitted.');
    const result=await api('/team-vaults/'+team.id+'/save',{revision:team.revision,payload});
    if(mark===generation.current){setEntries(next);setTeam({...team,revision:result.revision});setNotice('Encrypted changes saved.');}
  }
  async function changeSharingProtection(current,next,confirm) {
    const mark=generation.current,who=identity.current;
    const active=()=>mark===generation.current && who===identity.current;
    if(!who)throw new Error('Unlock your sharing identity first.');
    if(next!==confirm)throw new Error('New sharing passphrases must match.');
    const {estimator}=await import('./strength');
    if(!active())return;
    if(estimator.check(next).score<3)throw new Error('Choose a less predictable sharing passphrase.');
    const fresh=await api('/sharing/identity');
    if(!active())return;
    if(fresh.identity?.fingerprint!==who.fingerprint)throw new Error('Sharing identity changed. Lock and unlock again.');
    const body=await prepareSharingPassphraseChange(me.id,fresh.identity,current,next);
    if(!active())return;
    await api('/sharing/identity/passphrase',body);
    if(!active())return;
    lock();setRecord({...fresh.identity,encrypted:body.encrypted});
    setNotice('Sharing passphrase changed. Shared browser connections were revoked and unfinished shared account actions cancelled. Unlock with the new passphrase and pair again.');
  }
  async function transferOwnership(mode,target,formerRole) {
    const mark=generation.current,who=identity.current,current=team,trust=trusted.current;
    const active=()=>mark===generation.current && who===identity.current && !!handle.current;
    if(!active())throw new Error('Open and verify the shared vault first.');
    if(mode==='cancel'){
      await api('/team-vaults/'+current.id+'/ownership/'+target.id+'/cancel',{});
      if(active())setNotice('Ownership proposal stopped. The current owner and vault contents remain unchanged.');return;
    }
    const [fresh,members]=await Promise.all([api('/team-vaults/'+current.id),api('/sharing/directory')]);
    if(!active())return;
    const [latestDigest,displayedDigest]=await Promise.all([ownershipStateDigest(fresh),ownershipStateDigest(current)]);
    if(!active())return;
    if(latestDigest!==displayedDigest)throw new Error('Vault contents or access changed. Verify and reopen before approving ownership changes.');
    let body;
    if(mode==='propose'){
      const successor=members.members.find(person=>person.id===target);
      if(!successor)throw new Error('Choose a current accepted teammate.');
      body=await prepareOwnershipProposal(fresh,who,successor,formerRole);
    }else body=await acceptOwnershipTransfer(fresh,who,trust,target,members.members);
    if(!active())return;
    await api('/team-vaults/'+current.id+'/ownership'+(mode==='accept'?'/accept':''),body);
    if(!active())return;
    if(mode==='propose')setNotice('Ownership proposal signed. The selected teammate must accept within 15 minutes; ownership is unchanged until then.');
    else{
      lock();const lockedMark=generation.current;await load();
      if(lockedMark===generation.current)setNotice('Vault ownership transferred with a new encryption key. Shared browser connections were revoked and unfinished plans cancelled. Verify the new owner before reopening and pairing again.');
    }
  }
  const canEdit=team && ['owner','admin','editor'].includes(team.role) && me.role!=='viewer' && !team.rotation_required;
  const admin=team && ['owner','admin'].includes(team.role) && me.role!=='viewer';
  const target=directory.find(m=>m.id===recipient);
  return <section className="panel spaced">
    <div className="section-heading"><div><span className="eyebrow">SHARED WORKSPACE VAULTS · PREVIEW</span><h2>Give each teammate their own access.</h2></div>{unlocked && <button className="button secondary" onClick={lock}>Lock shared vaults</button>}</div>
    <p className="muted">Keep client and project credentials separate from personal vaults. Each member receives an encrypted vault key; your sharing passphrase stays in this browser. Agents never receive credentials. This new sharing protocol needs independent security review before valuable accounts are stored.</p>
    {error && <p className="notice error" role="alert">{error}</p>}{notice && <p className="notice" role="status">{notice}</p>}
    {record===undefined?<p>Loading sharing identity…</p>:!unlocked?<form className="operator-form" onSubmit={event=>{event.preventDefault();const form=event.currentTarget,password=new FormData(form).get('sharing_master'),confirm=new FormData(form).get('confirm');form.reset();const mark=generation.current;run(async()=>{let who;if(!record){if(password!==confirm)throw new Error('Sharing passphrases must match.');const {estimator}=await import('./strength');if(estimator.check(password).score<3)throw new Error('Choose a less predictable sharing passphrase.');const created=await createSharingIdentity(me.id,password);if(mark!==generation.current)return;await api('/sharing/identity',created.record);who=created.identity;await load();}else{const fresh=await api('/sharing/identity');if(mark!==generation.current)return;setRecord(fresh.identity);who=await unlockSharingIdentity(me.id,fresh.identity,password);}if(mark!==generation.current)return;identity.current=who;setUnlocked(true);});}}>
      <h3>{record?'Unlock your sharing identity':'Create your sharing identity'}</h3>
      <p>Use a separate passphrase of at least 15 characters. It encrypts your private sharing keys with Argon2id. Losing it means losing access; recovery and key replacement are not available yet.</p>
      <label>Sharing passphrase<input name="sharing_master" type="password" autoComplete={record?'current-password':'new-password'} minLength={15} maxLength={256} required/></label>
      {!record && <label>Confirm sharing passphrase<input name="confirm" type="password" autoComplete="new-password" minLength={15} maxLength={256} required/></label>}
      <button className="button" disabled={busy}>{busy?'Working locally…':record?'Unlock sharing identity':'Create encrypted identity'}</button>
    </form>:<>
      <p className="fine">Your identity fingerprint · share through a trusted channel</p><code className="fingerprint">{identity.current?.fingerprint}</code>
      <SharingPassphraseChange busy={busy} onChange={(current,next,confirm)=>run(()=>changeSharingProtection(current,next,confirm))}/>
      <div className="form-grid spaced"><div><h3>Workspace vaults</h3>{!list.length && <p>No shared vaults yet.</p>}{list.map(v=><button key={v.id} className="button secondary spaced" disabled={busy} onClick={()=>run(()=>choose(v.id))}>{v.name} · {v.role}{!v.accepted?' · invitation':''}{v.rotation_required?' · rotation needed':''}{v.ownership_pending?' · ownership proposal for you':''}</button>)}</div>
      {me.role!=='viewer' && <form className="operator-form" onSubmit={event=>{event.preventDefault();const form=event.currentTarget,name=new FormData(form).get('name'),mark=generation.current;run(async()=>{const id=[...crypto.getRandomValues(new Uint8Array(12))].map(n=>n.toString(16).padStart(2,'0')).join('');const body=await createTeamVault(identity.current,me.workspace,name,id);if(mark!==generation.current)return;await api('/team-vaults',body);form.reset();await load();await choose(id);});}}><label>New shared vault name<input name="name" minLength={2} maxLength={70} required placeholder="Client operations"/></label><button className="button" disabled={busy}>Create shared vault</button></form>}</div>
      {team && <div className="spaced"><h3>{team.name} · {team.role}</h3><p className="fine">Key epoch {team.epoch} · revision {team.revision}. Locks after 3 minutes of inactivity or when this tab is hidden.</p>
        {!!team.accepted && <VaultActivity key={'activity:'+team.id} kind="shared" vaultId={team.id} entries={entries}/>}
        {team.rotation_required && <p className="notice">Access was removed. The vault owner must rotate its encryption key before new credentials or invitations can be saved. Previously cached credentials cannot be erased; change the affected website passwords too.</p>}
        {!entries?<form className="operator-form" key={team.id} onSubmit={event=>{event.preventDefault();const form=event.currentTarget,value=new FormData(form).get('fingerprint') || '';run(()=>open(value));}}>
          {team.owner!==me.id && <><p>Confirm this owner fingerprint with the vault owner through another trusted channel. Comparing only information from this server does not authenticate a new identity.</p><code className="fingerprint">{team.owner_fingerprint}</code><label>Verified owner fingerprint<input name="fingerprint" pattern="[a-fA-F0-9]{64}" maxLength={64} autoComplete="off" required/></label></>}
          <button className="button" disabled={busy}>{team.accepted?'Verify and open shared vault':'Verify and accept invitation'}</button>
        </form>:<>
          <AccountActions entries={entries} vaultId={team.id} kind="shared" actor={me.id} canEdit={canEdit} canPrepare={canEdit && team.browser_policy?.browser_enabled!==false && team.browser_policy?.browser_save!==false && team.browser_policy?.browser_fill!==false} seal={manifest=>handle.current.sealAction(manifest)} onSave={save}/>
          {!entries.length && <p>This shared vault is empty. Add an account to store its encrypted credentials.</p>}
          <AccountReview key={team.id+':'+team.epoch} entries={entries} onSave={save} canEdit={canEdit} busy={busy}/>
          <OwnershipTransfer team={team} me={me} directory={directory} busy={busy} onPropose={(successor,role)=>run(()=>transferOwnership('propose',successor,role))} onAccept={proposal=>run(()=>transferOwnership('accept',proposal))} onCancel={proposal=>run(()=>transferOwnership('cancel',proposal))}/>
          {entries.filter(entry=>!isArchived(entry)).map(entry=><article className="entry-card spaced" key={entry.id}><strong>{entry.title}</strong><p>{entry.type==='login'?entry.origin+' · '+entry.username:'Authenticator code'}</p><div className="inline"><Secret entry={entry}/></div></article>)}
          {canEdit && <form className="operator-form spaced" onSubmit={event=>{event.preventDefault();const form=event.currentTarget,fields=new FormData(form);run(async()=>{const entry={id:crypto.randomUUID(),type:entryType,title:fields.get('title')};if(entryType==='login')Object.assign(entry,{origin:validOrigin(fields.get('origin')),username:fields.get('username'),password:fields.get('password')});else Object.assign(entry,parseOtpAuth(fields.get('setup')));await save([...entries,entry]);form.reset();});}}>
            <h3>Add account</h3><label>Entry type<select value={entryType} onChange={e=>setEntryType(e.target.value)}><option value="login">Login</option><option value="totp">Authenticator</option></select></label><label>Account label<input name="title" maxLength={100} required/></label>
            {entryType==='login'?<><label>Website origin<input name="origin" type="url" placeholder="https://app.example.com" required/></label><label>Username<input name="username" autoComplete="off" maxLength={254}/></label><label>Password<input name="password" type="password" autoComplete="new-password" maxLength={256} required/></label><button className="button secondary" type="button" onClick={e=>{e.currentTarget.form.elements.password.value=generatePassword(24);}}>Generate password locally</button></>:<label>Authenticator setup key or otpauth URI<input name="setup" type="password" autoComplete="off" required/></label>}
            <button className="button" disabled={busy}>Encrypt and save account</button>
          </form>}
          {admin && <>
            <h3 className="spaced">Members and invitations</h3>{team.grants.map(m=><div className="member-row" key={m.user_id}><div><strong>{m.email}</strong><p>{m.role} · {m.accepted?'accepted':'invited'}</p></div>{m.user_id!==team.owner && (team.role==='owner' || !['owner','admin'].includes(m.role)) && <button className="button secondary" disabled={busy} onClick={()=>run(async()=>{await api('/team-vaults/'+team.id+'/revoke/'+m.user_id,{});await load();await choose(team.id);setNotice('Access removed. Open the vault and rotate its key before saving more credentials.');})}>Remove access</button>}</div>)}
            {!team.rotation_required && <form className="operator-form spaced" onSubmit={event=>{event.preventDefault();const form=event.currentTarget,fields=new FormData(form),mark=generation.current;run(async()=>{if(!target || fields.get('fingerprint').trim().toLowerCase()!==target.fingerprint)throw new Error('Verify the recipient fingerprint through a trusted channel.');const grant=await handle.current.invite(target,fields.get('role'));if(mark!==generation.current)return;await api('/team-vaults/'+team.id+'/invite',grant);form.reset();setRecipient('');await choose(team.id);await load();});}}>
              <label>Teammate<select value={recipient} onChange={e=>setRecipient(e.target.value)} required><option value="">Choose a workspace member</option>{directory.filter(m=>m.public && !team.grants.some(g=>g.user_id===m.id)).map(m=><option key={m.id} value={m.id}>{m.email}</option>)}</select></label>
              {target && <code className="fingerprint">{target.fingerprint}</code>}<label>Recipient fingerprint verified through another channel<input name="fingerprint" pattern="[a-fA-F0-9]{64}" maxLength={64} autoComplete="off" required/></label><label>Vault role<select name="role"><option value="viewer">View</option>{target?.role!=='viewer' && <option value="editor">Edit</option>}{team.role==='owner' && target?.role!=='viewer' && <option value="admin">Admin · invite and remove members</option>}</select></label><button className="button" disabled={busy}>Send encrypted invitation</button>
            </form>}
          </>}
          {admin && <BrowserPolicy key={team.id+JSON.stringify(team.browser_policy)} value={team.browser_policy} busy={busy} onSave={value=>run(async()=>{await api('/team-vaults/'+team.id+'/browser-policy',value);await load();await choose(team.id);setNotice('Shared browser permissions updated. Disabled connections need fresh pairing before they can return.');})}/>}
          {team.role==='owner' && <button className="button spaced" disabled={busy} onClick={()=>run(async()=>{const mark=generation.current,body=await rotateTeamVault(team,identity.current,trusted.current,directory);if(mark!==generation.current)return;await api('/team-vaults/'+team.id+'/rotate',body);await load();await choose(team.id);setNotice('New vault key distributed only to remaining members. Website passwords still need changing if former members knew them.');})}>Rotate vault key for remaining members</button>}
        </>}
        <p className="fine spaced">Connect an accepted shared vault under Browser & devices, then unlock its sharing identity inside the companion. View/edit roles are enforced by this service; a recipient who has decrypted a secret can retain a copy.</p>
      </div>}
    </>}
  </section>;
}
