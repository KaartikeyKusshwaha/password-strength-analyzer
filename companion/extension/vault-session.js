import { encryptVault, unlockVault, validateEntries, validOrigin, generateTotp, parseOtpAuth } from '../../frontend/src/vault-crypto';
import { serviceOrigin } from './policy';
import {openAction,sealAction} from '../../frontend/src/action-crypto';
import {isArchived,trackChanges} from '../../frontend/src/entry-history';
import manifest from './public/manifest.json';

// This class runs exclusively inside an extension-origin frame or popup.
// The embedding website never receives the master passphrase or vault entries.
export class SaveSession {
  constructor(browser, fetcher = (...args) => globalThis.fetch(...args)) { this.browser = browser; this.fetcher = fetcher; this.generation=0;this.pending=new Set();this.lock(); }
  lock() {this.generation++;this.pending.forEach(controller=>controller.abort());this.pending.clear();this.material?.handle?.close();this.material = null; this.entries = null; this.revision = 0; this.config = null; this.policy = null;}
  active(generation) {if(generation!==this.generation)throw new Error('Vault locked. Unlock again to continue.');}
  async external(task){
    if(!this.material||!this.entries)throw new Error('Unlock your vault first.');
    const generation=this.generation,controller=new AbortController();this.pending.add(controller);
    try{const value=await task({signal:controller.signal,active:()=>this.active(generation)});this.active(generation);return value;}
    finally{this.pending.delete(controller);}
  }
  async request(body,path='/vault') {
    if(!this.config)throw new Error('Unlock your vault first.');
    if(!/^\/(vault|actions(?:\/context|\/[a-f0-9]{24}\/(claim|result|cancel))?)$/.test(path))throw new Error('Unsupported companion request.');
    const generation=this.generation,controller=new AbortController();this.pending.add(controller);
    try {
      // Browser fetch requires its global receiver, never this SaveSession.
      const fetcher = this.fetcher;
      const response = await fetcher(this.config.origin + '/api/companion'+path, {
        method: body ? 'POST' : 'GET', credentials: 'omit', redirect: 'error', signal: AbortSignal.any([controller.signal,AbortSignal.timeout(10000)]),
        headers: { Authorization: 'Bearer ' + this.config.token, 'X-Sentinel-Companion-Version':manifest.version, ...(body ? {'Content-Type':'application/json'} : {}) },
        ...(body ? {body: JSON.stringify(body)} : {}),
      });
      this.active(generation);
      if (response.status === 401 || response.status===404) throw Object.assign(new Error('Your browser connection expired or was revoked. Reconnect it in Browser & devices.'),{code:'CONNECTION_INVALID'});
      if (response.status===409 && path!=='/vault')throw new Error('This account action stopped, is leased elsewhere, or requires explicit resume. Refresh the approved queue before continuing. Staged passwords remain in your vault.');
      if (response.status === 409) throw new Error('Vault changed elsewhere. Unlock again to load the latest version; nothing was overwritten.');
      if (response.status === 403) throw new Error('This vault does not permit this browser action. Review its access and browser policy in the dashboard.');
      if (!response.ok) throw new Error('Could not synchronize the encrypted vault. Keep SentinelOps running and try again.');
      const value=await response.json();this.active(generation);return value;
    }finally{this.pending.delete(controller);}
  }
  async unlock(master,verifiedOwnerFingerprint='',selected=null) {
    this.lock();const generation=this.generation;
    const connection=selected || (await this.browser.storage.local.get('connection')).connection;
    this.active(generation);
    if (!connection) throw new Error('Connect this browser to your vault in the SentinelOps extension first.');
    this.config = {...connection,origin:serviceOrigin(connection.origin)};
    const value = await this.request();
    if (!value.envelope) throw new Error('Create your vault in the dashboard first.');
    if(connection.vaultId && connection.vaultId!==value.vault?.id)throw new Error('The browser connection returned a different vault. Reconnect it.');
    if((connection.vaultKind || 'personal')!==(value.kind || 'personal'))throw new Error('The browser connection scope changed. Reconnect it.');
    if(value.kind==='shared') {
      const {unlockSharingIdentity,openTeamVault}=await import('../../frontend/src/sharing-crypto');
      const who=await unlockSharingIdentity(value.sharing.user_id,value.sharing.identity,master);this.active(generation);
      const trusted=value.sharing.team.owner===who.user?who.fingerprint:verifiedOwnerFingerprint.trim().toLowerCase();
      const opened=await openTeamVault(value.sharing.team,who,trusted);
      if(generation!==this.generation){opened.handle.close();this.active(generation);}
      this.material={kind:'shared',handle:opened.handle,identity:who,trusted,epoch:value.sharing.team.epoch};this.entries=opened.entries;
    }else {
      const unlocked = await unlockVault(value.envelope, master);this.active(generation);
      this.material = {kind:'personal',key:unlocked.key, salt:unlocked.salt};this.entries=unlocked.entries;
    }
    this.policy = value.vault || null;
    this.revision = value.revision;
    return {entries:this.entries,revision:this.revision,policy:this.policy};
  }
  async refresh() {
    if(!this.material || !this.entries)throw new Error('Unlock your vault first.');
    const generation=this.generation,value=await this.request();
    if(value.revision!==this.revision || (value.kind || 'personal')!==(this.material.kind || 'personal') || this.policy?.id && value.vault?.id!==this.policy.id)throw new Error('Vault changed elsewhere. Unlock again to load the latest version; nothing was overwritten.');
    if(this.material.kind==='shared') {
      if(value.sharing?.team?.epoch!==this.material.epoch)throw new Error('Vault encryption key changed. Unlock again.');
      const {verifyTeam}=await import('../../frontend/src/sharing-crypto');
      await verifyTeam(value.sharing.team,this.material.identity,this.material.trusted);this.active(generation);
    }
    this.policy=value.vault || null;return this.policy;
  }
  permitted(action,origin) {
    if(this.policy && (this.policy.browser_enabled===false || !this.policy['browser_'+action] || origin && this.policy.origins.length && !this.policy.origins.includes(origin)))throw new Error('The connected vault does not permit this browser action for this website. Review its properties and your access in the dashboard.');
  }
  async fill(identifier,origin) {
    const generation=this.generation;await this.refresh();this.active(generation);this.permitted('fill',origin);
    const entry=this.entries.find(e=>e.id===identifier && e.type==='login' && !isArchived(e) && e.origin===origin && validOrigin(origin)===origin);
    if(!entry)throw new Error('No selected login for this exact HTTPS origin.');
    return {origin:entry.origin,username:entry.username,password:entry.password};
  }
  async code(identifier) {
    const generation=this.generation;await this.refresh();this.active(generation);this.permitted('fill');
    const entry=this.entries.find(e=>e.id===identifier && e.type==='totp' && !isArchived(e));if(!entry)throw new Error('Authenticator entry unavailable or archived.');
    const value=await generateTotp(entry);this.active(generation);return value;
  }
  async bindCode(identifier,origin){
    if(validOrigin(origin)!==origin)throw new Error('Choose an exact HTTPS website.');
    const generation=this.generation;await this.refresh();this.active(generation);this.permitted('save',origin);
    const entry=this.entries.find(e=>e.id===identifier&&e.type==='totp'&&!isArchived(e));
    if(!entry)throw new Error('Authenticator entry unavailable.');
    await this.persist(this.entries.map(e=>e.id===identifier?{...e,autofill_origin:origin}:e),generation);
  }
  async codeFor(identifier,origin){
    const generation=this.generation;await this.refresh();this.active(generation);this.permitted('fill',origin);
    const entry=this.entries.find(e=>e.id===identifier&&e.type==='totp'&&!isArchived(e)&&e.autofill_origin===origin);
    if(!entry||validOrigin(origin)!==origin)throw new Error('Link this authenticator to the exact website first.');
    if(entry.period-(Math.floor(Date.now()/1000)%entry.period)<5)throw new Error('This code expires shortly. Wait for the next code before filling.');
    const code=await generateTotp(entry);this.active(generation);return code;
  }
  async unlinkCode(identifier){
    const generation=this.generation;await this.refresh();this.active(generation);this.permitted('save');
    await this.persist(this.entries.map(entry=>{if(entry.id!==identifier||entry.type!=='totp')return entry;const {autofill_origin,...rest}=entry;return rest;}),generation);
  }
  async addAuthenticator(title,setup,origin=''){
    if(typeof title!=='string'||!title.trim()||title.trim().length>100||typeof setup!=='string'||!setup.trim()||setup.length>4096)throw new Error('Enter a name and supported setup key or TOTP URI.');
    if(origin&&validOrigin(origin)!==origin)throw new Error('Choose an exact HTTPS origin.');
    const generation=this.generation;await this.refresh();this.active(generation);this.permitted('save',origin||undefined);
    if(!origin&&this.policy?.origins?.length)throw new Error('Link this authenticator to an allowed website for this scoped vault.');
    const parsed=parseOtpAuth(setup.trim());
    if(this.entries.some(entry=>entry.type==='totp'&&!isArchived(entry)&&entry.secret===parsed.secret))throw new Error('This authenticator key is already saved in this vault.');
    const entry={id:crypto.randomUUID(),type:'totp',title:title.trim(),...parsed,...(origin?{autofill_origin:origin}:{})};
    validateEntries([entry]);await this.persist([...this.entries,entry],generation);this.active(generation);return entry.id;
  }
  async save(capture, confirmedUpdate = false) {
    if (!this.material || !this.entries) throw new Error('Unlock your private vault first.');
    if (!capture || !Number.isFinite(capture.expires) || capture.expires < Date.now()) throw new Error('This save request expired. Open the password assistant again.');
    capture={...capture,origin:validOrigin(capture.origin)};
    if(typeof capture.password!=='string' || !capture.password || capture.password.length>256 || typeof capture.username!=='string' || capture.username.length>254)throw new Error('Capture a supported password and username before saving.');
    this.permitted('save',capture.origin);const generation=this.generation;await this.refresh();this.active(generation);this.permitted('save',capture.origin);
    const matches = this.entries.filter(e => e.type === 'login' && !isArchived(e) && e.origin === capture.origin && e.username === capture.username);
    if(matches.some(e=>e.pending_change))throw new Error('This login has a staged account change. Confirm or discard that proposal in the dashboard or Approved account actions before replacing it.');
    if(matches.length>1)throw new Error('More than one saved login matches. Choose and edit the intended entry in the dashboard.');
    if (matches.length && !confirmedUpdate) return {needsConfirmation:true};
    const entry = {...matches[0],id: matches[0]?.id || crypto.randomUUID(), type:'login', title: matches[0]?.title || new URL(capture.origin).hostname, origin:capture.origin, username:capture.username, password:capture.password};
    const next = matches.length ? this.entries.map(e => e.id === entry.id ? entry : e) : [...this.entries, entry];
    validateEntries(next);
    await this.persist(next,generation);
    return {saved:true, updated:matches.length > 0};
  }
  async persist(next,generation=this.generation) {
    this.active(generation);next=trackChanges(this.entries,next);validateEntries(next);
    const envelope = this.material.kind==='shared'?await this.material.handle.encrypt(next):await encryptVault(next, this.material.key, this.material.salt);
    this.active(generation);
    const result = await this.request({revision:this.revision, envelope});
    this.active(generation);
    this.entries = next; this.revision = result.revision;
  }
  async actions() {
    await this.refresh();return (await this.request(undefined,'/actions')).actions;
  }
  async approveChanges(identifiers){
    if(!Array.isArray(identifiers)||!identifiers.length||identifiers.length>20||new Set(identifiers).size!==identifiers.length)throw new Error('Select 1–20 distinct saved logins.');
    const generation=this.generation;await this.refresh();this.active(generation);
    const descriptor=await this.request(undefined,'/actions/context');this.active(generation);
    if(descriptor.vault_id!==this.policy?.id||descriptor.kind!==this.material.kind)throw new Error('The vault approval scope changed. Reconnect this vault.');
    const items=identifiers.map(id=>{
      const entry=this.entries.find(item=>item.id===id&&item.type==='login'&&!isArchived(item));
      if(!entry||entry.pending_change)throw new Error('A login is unavailable or already has a staged change. Resolve that proposal first.');
      if(validOrigin(entry.origin)!==entry.origin)throw new Error('Use an exact HTTPS login origin.');
      this.permitted('save',entry.origin);this.permitted('fill',entry.origin);return {entry_id:id,origin:entry.origin};
    });
    const manifest={version:1,id:Array.from(crypto.getRandomValues(new Uint8Array(12)),byte=>byte.toString(16).padStart(2,'0')).join(''),...descriptor,approved_at:Math.floor(Date.now()/1000),expires_at:Math.floor(Date.now()/1000)+1800,items};
    const envelope=this.material.kind==='shared'?await this.material.handle.sealAction(manifest):await sealAction(manifest,this.material.key);this.active(generation);
    return this.request({id:manifest.id,vault_id:manifest.vault_id,kind:manifest.kind,entry_count:items.length,expires_at:manifest.expires_at,envelope},'/actions');
  }
  async actionPlan(job) {
    if(!this.material || !this.policy || job.vault_id!==this.policy.id || job.kind!==(this.material.kind || 'personal') || job.kind==='shared' && job.user!==this.material.identity.user)throw new Error('This plan belongs to a different vault or user.');
    const generation=this.generation;
    const plan=this.material.kind==='shared'?await this.material.handle.openAction(job):await openAction(job.manifest,this.material.key,job);
    this.active(generation);return plan;
  }
}
