import { useCallback, useEffect, useRef, useState } from "react";
import {
  Copy,
  Download,
  KeyRound,
  LockKeyhole,
  Plus,
  ShieldCheck,
  Smartphone,
  Trash2,
  UnlockKeyhole,
} from "lucide-react";
import { api } from "./api";
import {
  encryptVault,
  unlockVault,
  parseOtpAuth,
  generateTotp,
  validOrigin,
  validateEntries,
  decryptWithKey,
} from "./vault-crypto";
import { generatePassword } from "./lab";
import { accountHealth, changePasswordUrl } from './account-health';
import VaultActivity from './VaultActivity';
import VaultRecovery from './VaultRecovery';
import VaultImport from './VaultImport';
import BreachReview from './BreachReview';
import AccountActions from './AccountActions';
import {sealAction} from './action-crypto';
import {withoutChangeState} from './credential-changes';
import AccountReview from './AccountReview';
import {isArchived,trackChanges} from './entry-history';

function Code({ entry }) {
  const [code, setCode] = useState("••••••"),
    [seconds, setSeconds] = useState(0);
  useEffect(() => {
    let active = true;
    function update() {
      generateTotp(entry).then((value) => {
        if (active) setCode(value);
      });
      setSeconds(entry.period - (Math.floor(Date.now() / 1000) % entry.period));
    }
    update();
    const timer = setInterval(update, 1000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [entry]);
  return (
    <div className="otp-code">
      <strong>
        {code.slice(0, 3)} {code.slice(3)}
      </strong>
      <small>{seconds}s</small>
      <button
        className="icon-button"
        aria-label={"Copy code for " + entry.title}
        onClick={() => navigator.clipboard.writeText(code)}
      >
        <Copy size={16} />
      </button>
    </div>
  );
}
export default function Vault({ space, otherVaults = [], me, initialType='login' }) {
  const vaultPath = '/vault' + (space?.id ? '?vault_id='+encodeURIComponent(space.id) : '');
  const [envelope, setEnvelope] = useState(undefined),
    [revision, setRevision] = useState(0),
    [entries, setEntries] = useState(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [type, setType] = useState(initialType),
    [adding, setAdding] = useState(false),
    [health, setHealth] = useState(null),
    [copyNotice, setCopyNotice] = useState(''),
    [reveal, setReveal] = useState(null);
  const material = useRef(null),
    lockTimer = useRef(null),generation=useRef(0);
  const lock = useCallback(() => {
    generation.current++;
    material.current = null;
    setBusy(false);
    setEntries(null);
    setReveal(null);
    setAdding(false);
    setHealth(null);
    clearTimeout(lockTimer.current);
  }, []);
  useEffect(() => {
    const hidden=()=>{if(document.hidden)lock();};document.addEventListener('visibilitychange',hidden);
    let active=true;
    api(vaultPath)
      .then((r) => {
        if(!active)return;
        setEnvelope(r.envelope);
        setRevision(r.revision);
      })
      .catch((e) => {if(active)setError(e.message);});
    return () => {
      active=false;generation.current++;document.removeEventListener('visibilitychange',hidden);
      material.current = null;
      clearTimeout(lockTimer.current);
    };
  }, []);
  useEffect(() => {
    if (!entries) return;
    const schedule = () => {
      clearTimeout(lockTimer.current);
      lockTimer.current = setTimeout(lock, (space?.lock_seconds || 180)*1000);
    };
    const hidden = () => {
      if (document.hidden) lock();
    };
    schedule();
    document.addEventListener("pointerdown", schedule);
    document.addEventListener("keydown", schedule);
    document.addEventListener("visibilitychange", hidden);
    return () => {
      clearTimeout(lockTimer.current);
      document.removeEventListener("pointerdown", schedule);
      document.removeEventListener("keydown", schedule);
      document.removeEventListener("visibilitychange", hidden);
    };
  }, [entries, lock]);
  useEffect(() => {
    if (!entries || busy) return;
    let active = true;
    const timer = setInterval(async () => {
      try {
        const latest = await api(vaultPath);
        if (!active || !material.current || latest.revision === revision) return;
        const fresh = await decryptWithKey(latest.envelope, material.current.key, material.current.salt);
        if (active && material.current) { setEnvelope(latest.envelope); setRevision(latest.revision); setEntries(fresh); }
      } catch (error) { if (active) { lock(); setError('Vault synchronization stopped. Unlock again to load the latest encrypted data.'); } }
    }, 8000);
    return () => { active = false; clearInterval(timer); };
  }, [entries, revision, busy, lock]);
  useEffect(() => {
    let active = true;
    setHealth(null);
    if (entries) import('./strength').then(({estimator}) => {
      const result = accountHealth(entries, password => estimator.check(password));
      if (active) setHealth(result);
    });
    return () => { active = false; };
  }, [entries]);
  async function open(e) {
    e.preventDefault();
    const mark=++generation.current;
    setBusy(true);
    setError("");
    const form = e.currentTarget;
    const fields = new FormData(form);
    form.reset();
    try {
      const latest = await api(vaultPath);
      if(mark!==generation.current)return;
      setRevision(latest.revision);
      setEnvelope(latest.envelope);
      const password = fields.get("master");
      if (!latest.envelope) {
        if (password !== fields.get("confirm"))
          throw new Error("Master passphrases must match.");
        const { estimator } = await import("./strength");
        if (password.length > 128 || estimator.check(password).score < 3)
          throw new Error(
            "Choose a less predictable master passphrase (15–128 characters).",
          );
        const {createProtectedVault} = await import('./vault-v2');
        const protectedVault = await createProtectedVault([], password, space.id);
        if(mark!==generation.current)return;
        const {key,salt,envelope:enc} = protectedVault;
        const saved = await api(vaultPath, {
          revision: latest.revision,
          envelope: enc,
        });
        if(mark!==generation.current)return;
        setRevision(saved.revision);
        setEnvelope(enc);
        material.current = { key, salt };
        setEntries([]);
      } else {
        const unlocked = await unlockVault(latest.envelope, password);
        if(mark!==generation.current)return;
        material.current = { key: unlocked.key, salt: unlocked.salt };
        setEntries(unlocked.entries);
      }
      form.reset();
    } catch (e) {
      if(mark===generation.current)setError(e.message);
    } finally {
      if(mark===generation.current)setBusy(false);
    }
  }
  async function save(next) {
    const mark=generation.current,current=material.current;
    setBusy(true);
    setError("");
    try {
      next=trackChanges(entries,next);
      validateEntries(next);
      if(!current)throw new Error('Unlock the vault before saving.');
      const encrypted = await encryptVault(
        next,
        current.key,
        current.salt,
      );
      if(mark!==generation.current)return false;
      const saved = await api(vaultPath, { revision, envelope: encrypted });
      if(mark!==generation.current)return false;
      setRevision(saved.revision);
      setEnvelope(encrypted);
      setEntries(next);
      return true;
    } catch (e) {
      if(mark===generation.current)setError(e.message);
      return false;
    } finally {
      if(mark===generation.current)setBusy(false);
    }
  }
  async function add(e) {
    e.preventDefault();
    const form = e.currentTarget;
    const f = Object.fromEntries(new FormData(form));
    try {
      const value =
        type === "login"
          ? {
              id: crypto.randomUUID(),
              type,
              title: f.title,
              origin: validOrigin(f.origin),
              username: f.username,
              password: f.password,
            }
          : {
              id: crypto.randomUUID(),
              type,
              title: f.title,
              ...parseOtpAuth(f.secret),
            };
      if (await save([...entries, value])) {
        form.reset();
        setAdding(false);
      }
    } catch (e) {
      setError(e.message);
    }
  }
  async function copyEntry(event,entry) {
    event.preventDefault();
    const mark=generation.current,session=material.current,form=event.currentTarget;
    const destination=form.elements.destination.value,master=form.elements.destination_master.value;
    const active=()=>mark===generation.current && material.current===session && !!session;
    form.reset();setBusy(true);setError('');setCopyNotice('');
    try {
      if(!active())throw new Error('Unlock the source vault before copying.');
      const target=otherVaults.find(v=>v.id===destination);
      if(!target)throw new Error('Choose another active vault.');
      const path='/vault?vault_id='+encodeURIComponent(destination),current=await api(path);
      if(!active())return;
      if(!current.envelope)throw new Error('Create the destination vault’s master passphrase before copying.');
      const unlocked=await unlockVault(current.envelope,master);
      if(!active())return;
      const {history,...copy}=withoutChangeState(entry);
      const next=trackChanges(unlocked.entries,[...unlocked.entries,{...copy,id:crypto.randomUUID()}]);
      const payload=await encryptVault(next,unlocked.key,unlocked.salt);
      if(!active())return;
      await api(path,{revision:current.revision,envelope:payload});
      if(active())setCopyNotice('Encrypted copy saved to '+target.name+'. Original entry retained.');
    }catch(error){if(active())setError(error.message);}
    finally{if(active())setBusy(false);}
  }
  async function changeProtection(event) {
    event.preventDefault();
    const mark=generation.current,session=material.current,form=event.currentTarget;
    const current=form.elements.current_master.value,next=form.elements.new_master.value,confirm=form.elements.confirm_master.value;
    const active=()=>mark===generation.current && material.current===session && !!session;
    form.reset();setBusy(true);setError('');
    try {
      if(!active())throw new Error('Unlock the vault before updating protection.');
      if(next!==confirm)throw new Error('New master passphrases must match.');
      const {estimator}=await import('./strength');
      if(!active())return;
      if(next.length>128 || estimator.check(next).score<3)throw new Error('Choose a less predictable new master passphrase.');
      const {changeMasterPassphrase,createProtectedVault}=await import('./vault-v2');
      if(!active())return;
      let replacement;
      if(envelope.version===2)replacement=await changeMasterPassphrase(envelope,current,next);
      else {
        const old=await unlockVault(envelope,current);
        if(!active())return;
        replacement=(await createProtectedVault(old.entries,next,space.id)).envelope;
      }
      if(!active())return;
      const result=await api(vaultPath,{revision,envelope:replacement});
      if(!active())return;
      lock();setEnvelope(replacement);setRevision(result.revision);
      setCopyNotice('Vault protection updated. Unlock with your new passphrase and reconnect browser companions for this vault.');
    }catch(error){if(active())setError('Vault protection update did not finish. Unlock again to check the latest state. '+error.message);}
    finally{if(active())setBusy(false);}
  }
  async function restoreBackup(event) {
    event.preventDefault();
    const mark=generation.current,session=material.current,form=event.currentTarget;
    const file=form.elements.backup.files[0],master=form.elements.master.value;
    const active=()=>mark===generation.current && material.current===session && !!session;
    form.reset();setBusy(true);setError('');
    try {
      if(!active())throw new Error('Unlock the destination vault before restoring.');
      if(!file || file.size>150000)throw new Error('Choose an encrypted backup under 150 KB.');
      const payload=JSON.parse(await file.text());
      if(!active())return;
      const unlocked=await unlockVault(payload.envelope,master);
      if(!active())return;
      await save(unlocked.entries);
    }catch(error){if(active())setError(error.message);}
    finally{if(active())setBusy(false);}
  }
  function backup() {
    const blob = new Blob(
      [
        JSON.stringify(
          { product: "SentinelOps encrypted vault", envelope },
          null,
          2,
        ),
      ],
      { type: "application/json" },
    );
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = 'sentinelops-vault-'+(space?.id || 'personal')+'.json';
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }
  return (
    <>
      <div className="notice">
        <ShieldCheck size={17} /> {space?.name || 'Personal'} vault · Separate master passphrase ·
        Encrypted in your browser before storage. AI agents never receive vault
        contents. This new vault implementation needs an independent security
        review before storing valuable credentials.
      </div>
      {error && (
        <div className="notice error" role="alert">
          {error}
        </div>
      )}
      {copyNotice && <p className="notice" role="status">{copyNotice}</p>}
      {!!space?.archived && <p className="notice">This vault is archived. You may unlock it to view or export; restore it in Vault properties before making changes.</p>}
      <VaultActivity kind="personal" vaultId={space?.id} entries={entries}/>
      {entries === null ? (
        <div className="two-col">
          <section className="panel">
            <span className="tool-icon green">
              <LockKeyhole size={26} />
            </span>
            <h2>
              {envelope
                ? "Unlock your personal vault"
                : "Create an encrypted personal vault"}
            </h2>
            <p className="muted">
              Passwords and authenticator keys are encrypted together. Your
              sign-in password does not unlock this vault.
            </p>
            {envelope !== undefined && (
              <form onSubmit={open}>
                <label>
                  Master passphrase
                  <input
                    name="master"
                    type="password"
                    autoComplete={
                      envelope ? "current-password" : "new-password"
                    }
                    minLength={15}
                    maxLength={256}
                    required
                  />
                </label>
                {!envelope && (
                  <label>
                    Confirm master passphrase
                    <input
                      name="confirm"
                      type="password"
                      autoComplete="new-password"
                      minLength={15}
                      maxLength={256}
                      required
                    />
                  </label>
                )}
                <button className="button" disabled={busy}>
                  <UnlockKeyhole size={16} />
                  {busy
                    ? "Working locally…"
                    : envelope
                      ? "Unlock vault"
                      : "Create vault"}
                </button>
              </form>
            )}
            <p className="fine">
              {envelope?.version === 1 ? 'Legacy PBKDF2-SHA256; 600,000 iterations.' : 'Argon2id (64 MiB, 3 passes) wraps a random AES-256 vault key.'} {envelope?.version===1 ? "Upgrade while you still know the master; legacy vaults cannot use recovery kits." : "Recovery requires a previously prepared offline recovery kit and its separate key."} Keep an encrypted backup and remember its passphrase.
            </p>
            {envelope && (
              <button className="text-button" onClick={backup}>
                <Download size={15} />
                Export encrypted backup while locked
              </button>
            )}
          </section>
          <section className="panel">
            <Smartphone size={29} />
            <h2 className="spaced">Use codes for your other accounts</h2>
            <p>
              Enable authenticator-based two-step verification in Google or
              another compatible service, then add its setup key or{" "}
              <code>otpauth://</code> URI here.
            </p>
            <p className="muted">
              Confirm the first generated code with that service to finish
              enrollment. Merely adding a key here does not enable protection on
              an external account.
            </p>
            <a
              className="text-button"
              href="https://myaccount.google.com/signinoptions/two-step-verification"
              target="_blank"
              rel="noreferrer"
            >
              Open Google’s two-step settings ↗
            </a>
            <p className="fine">
              SMS, push approvals, passkeys, hardware keys and proprietary
              authenticators cannot all be managed as TOTP. For stronger factor
              separation, keep your authenticator on an independent device.
            </p>
          </section>
        </div>
      ) : (
        <>
          <section className="panel vault-toolbar">
            <div>
              <BadgeUnlocked />
              <small>
                {entries.length}/200 entries · Auto-lock after {space?.lock_seconds || 180} seconds idle or when the tab is hidden
              </small>
            </div>
            <div className="inline">
              <button className="button secondary" onClick={backup}>
                <Download size={15} />
                Encrypted backup
              </button>
              <button className="button secondary" onClick={lock}>
                <LockKeyhole size={15} />
                Lock
              </button>
              <button className="button" disabled={!!space?.archived} onClick={() => setAdding(!adding)}>
                <Plus size={15} />
                {initialType==='totp'?'Add authenticator':'Add account'}
              </button>
            </div>
          </section>
          <section className="panel spaced">
            <span className="eyebrow">ACCOUNT SECURITY OPERATOR · LOCAL REVIEW</span>
            <h2>Which accounts need attention?</h2>
            <p className="muted">Your logins are checked locally after unlock. Select an account action below; the browser assistant suggests a new password on supported forms and updates this encrypted vault with your approval.</p>
            {health && <div className="vault-health"><div><strong>{health.length}</strong>Saved logins</div><div><strong>{health.filter(h => h.weak).length}</strong>Guessable passwords</div><div><strong>{health.filter(h => h.reused).length}</strong>Logins sharing a password</div><div><strong>{entries.filter(e => e.type === 'totp' && !isArchived(e)).length}</strong>Authenticator entries</div></div>}
            <p className="fine">This checks strength and reuse, not breaches or whether 2FA is enabled at the service. Account changes still require the website’s authentication and confirmation.</p>
          </section>
          {me && <AccountActions entries={entries} vaultId={space.id} kind="personal" actor={me.id} canEdit={!space.archived} canPrepare={!space.archived && !!space.browser_enabled && !!space.browser_save && !!space.browser_fill} seal={manifest=>sealAction(manifest,material.current.key)} onSave={async next=>{if(!await save(next))throw new Error('Encrypted vault changes were not saved. Reload before retrying.');}}/>}
          <AccountReview entries={entries} onSave={save} canEdit={!space?.archived} busy={busy} health={health}/>
          {adding && (
            <section className="panel">
              <h2>Add an account</h2>
              <form onSubmit={add}>
                <div className="form-grid">
                  <label>
                    Entry type
                    <select
                      value={type}
                      onChange={(e) => setType(e.target.value)}
                    >
                      <option value="login">Website login</option>
                      <option value="totp">Authenticator (TOTP)</option>
                    </select>
                  </label>
                  <label>
                    Display name
                    <input name="title" required maxLength={100} />
                  </label>
                </div>
                {type === "login" ? (
                  <>
                    <div className="form-grid">
                      <label>
                        Website origin
                        <input
                          name="origin"
                          type="url"
                          required
                          placeholder="https://accounts.google.com"
                        />
                      </label>
                      <label>
                        Username or email
                        <input name="username" maxLength={254} />
                      </label>
                    </div>
                    <label>
                      Password
                      <input
                        name="password"
                        type="password"
                        autoComplete="new-password"
                        required
                        maxLength={256}
                      />
                    </label>
                    <button
                      className="text-button"
                      type="button"
                      onClick={(e) => {
                        e.currentTarget.form.elements.password.value =
                          generatePassword();
                      }}
                    >
                      Generate a 24-character password locally
                    </button>
                  </>
                ) : (
                  <>
                    <label>
                      Setup key or otpauth URI
                      <input
                        name="secret"
                        type="password"
                        autoComplete="off"
                        required
                        maxLength={2000}
                      />
                    </label>
                    <p className="fine">
                      Never paste an expiring six-digit code here. Add the long
                      setup secret from the service’s enrollment screen.
                      Supported TOTP: SHA1/256/512, 6/8 digits, 30/60 seconds.
                    </p>
                  </>
                )}
                <div className="modal-actions">
                  <button
                    className="button secondary"
                    type="button"
                    onClick={() => setAdding(false)}
                  >
                    Cancel
                  </button>
                  <button className="button" disabled={busy}>
                    Encrypt and save
                  </button>
                </div>
              </form>
            </section>
          )}
          <VaultImport disabled={busy || !!space?.archived} existingCount={entries.length} onImport={items=>save([...entries,...items])}/>
          <BreachReview entries={entries}/>
          <div className="two-col">
            {entries.filter(entry=>!isArchived(entry)).map((entry) => (
              <section className="panel vault-entry" key={entry.id}>
                <div className="panel-heading">
                  <div className="inline">
                    {entry.type === "totp" ? (
                      <Smartphone size={20} />
                    ) : (
                      <KeyRound size={20} />
                    )}
                    <h2>{entry.title}</h2>
                  </div>
                  <span className="badge green">
                    {entry.type === "totp" ? "Authenticator" : "Login"}
                  </span>
                </div>
                {entry.type === "totp" ? (
                  <>
                    <Code entry={entry} />
                    <p className="fine">
                      Generated locally from your enrolled setup key. Verify
                      your device clock if a code is rejected.
                    </p>
                  </>
                ) : (
                  <>
                    <p className="mono wrap">{entry.origin}</p>
                    <p className="muted">{entry.username}</p>
                    {health?.find(h => h.id === entry.id)?.weak && <p className="notice">This password is guessable. Start a password change below.</p>}
                    {health?.find(h => h.id === entry.id)?.reused && <p className="notice">This password is shared with another saved account. Use a unique replacement.</p>}
                    <a className="button secondary" href={changePasswordUrl(entry.origin)} target="_blank" rel="noreferrer">Start password change ↗</a>
                    <p className="fine">Opens this service’s password-change discovery URL. Support varies by website. Complete sign-in or MFA there; the connected browser assistant can generate and save the replacement on recognized forms.</p>
                    <div className="inline">
                      <input
                        aria-label={"Password for " + entry.title}
                        readOnly
                        type={reveal === entry.id ? "text" : "password"}
                        value={entry.password}
                      />
                      <button
                        className="text-button"
                        onClick={() =>
                          setReveal(reveal === entry.id ? null : entry.id)
                        }
                      >
                        {reveal === entry.id ? "Hide" : "Reveal"}
                      </button>
                      <button
                        className="icon-button"
                        aria-label={"Copy password for " + entry.title}
                        onClick={() =>
                          navigator.clipboard.writeText(entry.password)
                        }
                      >
                        <Copy size={16} />
                      </button>
                    </div>
                  </>
                )}
                <details>
                  <summary>Copy to another vault</summary>
                  <p className="fine">Unlock the destination below. It receives a separately encrypted copy; changing either copy later does not synchronize the other.</p>
                  <form onSubmit={event=>copyEntry(event,entry)}><label>Destination vault<select name="destination" required>{otherVaults.map(v=><option key={v.id} value={v.id}>{v.name}</option>)}</select></label><label>Destination master passphrase<input name="destination_master" type="password" required autoComplete="off" minLength={15} maxLength={256}/></label><button className="button secondary" disabled={busy || !otherVaults.length}>Encrypt a copy in destination</button></form>
                </details>
                <details>
                  <summary>Remove entry</summary>
                  <p className="fine">
                    Removing this entry cannot disable 2FA or change the
                    password at the original service. Keep that service’s
                    recovery method available.
                  </p>
                  <button
                    className="button secondary"
                    disabled={busy}
                    onClick={() =>
                      save(entries.filter((e) => e.id !== entry.id))
                    }
                  >
                    <Trash2 size={14} />
                    Confirm removal
                  </button>
                </details>
              </section>
            ))}
          </div>
          {!entries.length && (
            <section className="panel">
              <h2>Your private space is ready</h2>
              <p className="muted">
                Add a website login or an authenticator key. You choose what is
                stored.
              </p>
            </section>
          )}
          <section className="panel">
            <h2>{envelope?.version === 2 ? 'Change vault master passphrase' : 'Upgrade vault encryption'}</h2>
            <p className="fine">{envelope?.version === 2 ? 'A new Argon2id unlock key re-wraps your vault key without re-encrypting every saved item.' : 'Upgrade this legacy vault to an Argon2id unlock key and a random AES-256 vault key. Existing entries are re-encrypted locally.'} This locks the vault and revokes its browser connections. Previously exported backups still require their original passphrase. There is no passphrase recovery.</p>
            <form className="operator-form" onSubmit={changeProtection}><label>Current vault master passphrase<input name="current_master" type="password" required autoComplete="off" minLength={15} maxLength={256}/></label><label>New vault master passphrase<input name="new_master" type="password" required autoComplete="new-password" minLength={15} maxLength={128}/></label><label>Confirm new vault master passphrase<input name="confirm_master" type="password" required autoComplete="new-password" minLength={15} maxLength={128}/></label><button className="button secondary" disabled={busy || !!space?.archived}>{envelope?.version === 2 ? 'Update vault protection' : 'Upgrade encrypted vault'}</button></form>
          </section>
          <section className="panel">
            <h2>Restore an encrypted backup</h2>
            <p className="fine">
              A restore replaces the current vault only after you unlock the
              backup. Export your current vault first. The original backup
              passphrase is required.
            </p>
            <form onSubmit={restoreBackup}
            >
              <label>
                Encrypted backup
                <input
                  type="file"
                  name="backup"
                  accept="application/json"
                  required
                />
              </label>
              <label>
                Backup’s master passphrase
                <input
                  name="master"
                  type="password"
                  autoComplete="off"
                  required
                />
              </label>
              <label className="check">
                <input type="checkbox" required />I exported my current vault
                and want to replace its entries.
              </label>
              <button className="button secondary" disabled={busy || !!space?.archived}>
                Unlock backup and replace entries
              </button>
            </form>
          </section>
        </>
      )}
      {envelope?.version===2&&<VaultRecovery key={generation.current} space={space} vaultPath={vaultPath} unlocked={entries!==null} disabled={busy||!!space?.archived} onReplaced={(replacement,nextRevision,notice)=>{lock();setEnvelope(replacement);setRevision(nextRevision);setCopyNotice(notice);}}/>}
    </>
  );
}
function BadgeUnlocked() {
  return (
    <h2 className="inline">
      <UnlockKeyhole size={19} />
      Personal vault unlocked
    </h2>
  );
}
