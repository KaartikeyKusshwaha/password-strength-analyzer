import AccessReminders from './AccessReminders';
import AccountDiscovery from './AccountDiscovery';
import AccessWorkflows from './AccessWorkflows';
import SecurityAssistant from './SecurityAssistant';
import CodeFill from './CodeFill';
import CloudConnect from './CloudConnect';
import {CLOUD_ORIGIN} from './cloud-connect';
import VaultHealth from './VaultHealth';
import AuthenticatorSetup from './AuthenticatorSetup';
import LoginSaveOffers from './LoginSaveOffers';
import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { validOrigin } from "../../frontend/src/vault-crypto";
import {SaveSession} from './vault-session';
import {isArchived} from '../../frontend/src/entry-history';
import {ActionQueue} from './action-queue';
import { generatePassword } from "../../frontend/src/lab";
import "./popup.css";
import { restoreConnection, prepareConnection, allowConnection } from "./connection";
import {fillSavedLogin} from './autofill-client';
import manifest from './public/manifest.json';
import {runtimeVersion} from './runtime-version';

export function Popup() {
  const versions=runtimeVersion(chrome,manifest.version);
  const [config, setConfig] = useState(null),
    [pendingConnection, setPendingConnection] = useState(null),
    [ready, setReady] = useState(false),
    [entries, setEntries] = useState(null),
    [revision, setRevision] = useState(0),
    [vaultPolicy, setVaultPolicy] = useState(null),
    [connections, setConnections] = useState([]),
    [reconnectRequired, setReconnectRequired] = useState(false),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [notice, setNotice] = useState(""),
    [capture, setCapture] = useState(null),
    [active, setActive] = useState(null),
    [code, setCode] = useState(null),
    [fillStatus,setFillStatus] = useState(null);
  const [update,setUpdate]=useState(false);
  const [actionRefresh,setActionRefresh]=useState(0),[autoAction,setAutoAction]=useState(null);
  function approvedAction(id){if(/^[a-f0-9]{24}$/.test(id||''))setAutoAction({id,generation:session.current.generation,vault:session.current.policy?.id});setActionRefresh(value=>value+1);}
  const session = useRef(new SaveSession(chrome));
  function lockVault() {session.current.lock();setEntries(null);setCapture(null);setCode(null);setUpdate(false);setFillStatus(null);}
  function reportError(error) {
    if(error.code==='CONNECTION_INVALID'){lockVault();setReconnectRequired(true);}
    setError(error.message);
  }
  async function reconnect() {
    lockVault();setConfig(null);setVaultPolicy(null);setReconnectRequired(false);setError('');
    await chrome.storage.local.remove('connection');
    const saved=await chrome.storage.local.get('connections');setConnections(saved.connections || []);
  }
  useEffect(()=>{if(config)chrome.storage.local.get(['connections','connection']).then(saved=>setConnections(saved.connections || (saved.connection?[saved.connection]:[])));},[config]);
  useEffect(() => {
    if(!versions.matches){setReady(true);return;}
    const hidden=()=>{if(document.hidden)lockVault();};document.addEventListener('visibilitychange',hidden);
    restoreConnection(chrome)
      .then(result => { setConfig(result.connection); setPendingConnection(result.pending); })
      .catch(async error => {
        setError(error.message);
        const saved = await chrome.storage.local.get('pendingConnection');
        setPendingConnection(saved.pendingConnection || null);
      })
      .finally(() => setReady(true));
    chrome.storage.local.get(['connections','connection']).then(saved=>setConnections(saved.connections || (saved.connection?[saved.connection]:[])));
    chrome.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
      try {
        setActive({ id: tabs[0].id, origin: validOrigin(tabs[0].url) });
      } catch {
        setActive(null);
      }
    });
    const timer = setTimeout(() => {
      lockVault();
      setNotice("Locked after three minutes. Unlock again to continue.");
    }, 180000);
    return () => {
      clearTimeout(timer);
      document.removeEventListener('visibilitychange',hidden);
      session.current.lock();
    };
  }, []);
  useEffect(() => {
    if (!entries || !vaultPolicy) return;
    const timer = setTimeout(lockVault,vaultPolicy.lock_seconds*1000);
    return () => clearTimeout(timer);
  }, [entries, vaultPolicy]);
  useEffect(()=>{if(!entries || busy)return;const timer=setInterval(()=>session.current.refresh().catch(error=>{lockVault();reportError(error);}),8000);return ()=>clearInterval(timer);},[entries,busy]);
  async function open(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    const form = e.currentTarget;
    const master=form.elements.master.value, fingerprint=form.elements.fingerprint?.value || '';form.reset();
    try {
      const unlocked = await session.current.unlock(master,fingerprint,config);
      setVaultPolicy(unlocked.policy);
      setEntries(unlocked.entries);
      setRevision(unlocked.revision);
    } catch (e) {
      reportError(e);
    } finally {
      setBusy(false);
    }
  }
  async function saveEntry(entry,confirmedUpdate=false) {
    if (entry.expires && entry.expires < Date.now()) {
      setCapture(null);
      setError("Save request expired. Capture again from the website.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const result=await session.current.save(entry,confirmedUpdate);
      if(result.needsConfirmation){setCapture(entry);setUpdate(true);return;}
      setRevision(session.current.revision);
      setEntries(session.current.entries);
      setCapture(null);
      setUpdate(false);
      setNotice("Encrypted and saved. No plaintext was sent to the server.");
    } catch (e) {
      reportError(e);
    } finally {
      setBusy(false);
    }
  }
  if(!versions.matches)return <main><header><span className="logo">S</span><div><h1>SentinelOps</h1><small>LOADED {versions.loaded||'VERSION UNAVAILABLE'} · FILES {versions.bundled}</small></div></header><section role="alert"><h2>Finish the companion update</h2><p>The browser’s loaded extension and these files do not match. Vault controls are paused so you do not use a mixture of versions.</p><ol><li>Open your browser’s Extensions page and reload SentinelOps Security Companion.</li><li>Refresh the website where you want to save or fill a login.</li><li>Open this popup again. Its loaded version should be {versions.bundled}.</li></ol><p>No vault was unlocked by this popup.</p></section></main>;
  return (
    <main>
      <header>
        <span className="logo">S</span>
        <div>
          <h1>SentinelOps</h1>
          <small>YOUR SECURITY COMPANION · {versions.loaded}</small>
        </div>
      </header>
      <AccessReminders/>
      <AccessWorkflows onTransferred={verified=>{lockVault();setNotice(verified?'Vault ownership transferred. Reconnect this vault and verify the new owner fingerprint before reopening.':'Ownership acceptance could not be confirmed. Vault locked; refresh the handoff and reconnect if its browser connection was revoked.');}} vaultSession={session.current} selectedVault={config} vaultUnlocked={!!entries} onApproved={approvedAction} onVaultChanged={()=>{setEntries(session.current.entries);setRevision(session.current.revision);}} onRotated={()=>{lockVault();setNotice('Shared vault key rotated. Unlock again for its new key.');}}/>
      <AccountDiscovery active={active}/>
      <SecurityAssistant/>
      <LoginSaveOffers browser={chrome} origin={active?.origin}/>
      <details><summary>Control room · vault administration and history</summary><p className="fine">Manage vaults, shared access, results history and account settings. Everyday checks and credential actions stay here.</p><button className="secondary" onClick={()=>chrome.tabs.create({url:(config?.origin||pendingConnection?.origin||CLOUD_ORIGIN)+'/#tool=passwords'})}>Open control room</button></details>
      {connections.length > 0 && <label>Connected vault<select value={config ? connections.findIndex(item=>item.token===config.token) : ''} disabled={busy} onChange={async event=>{const next=connections[Number(event.target.value)];if(!next)return;lockVault();setVaultPolicy(null);await chrome.storage.local.set({connection:next});await chrome.storage.local.remove('pendingConnection');setPendingConnection(null);setConfig(next);setReconnectRequired(false);setError('');}}><option value="" disabled>Choose a connected vault</option>{connections.map((item,index)=><option key={index} value={index}>{item.vaultName || 'Vault name not verified'}{item.vaultKind==='shared'?' · shared':''} · {new URL(item.origin).host}</option>)}</select></label>}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {notice && (
        <p className="notice" role="status">
          {notice}
        </p>
      )}
      {!ready ? (
        <p>Opening companion…</p>
      ) : !config && pendingConnection ? (
        <>
          <h2>Finish connecting your vault</h2>
          <p>Pairing details saved for <strong>{pendingConnection.origin}</strong>.</p>
          <p>Allow access to this app, then we will verify your token. If the browser closes this popup during approval, reopen it; you do not need to paste the token again.</p>
          <button disabled={busy} onClick={() => {
            setBusy(true); setError('');
            allowConnection(chrome, pendingConnection)
              .then(result => { setConfig(result.connection); setPendingConnection(result.pending); setNotice('Connection verified and saved. Unlock your vault below.'); })
              .catch(error => setError(error.message))
              .finally(() => setBusy(false));
          }}>{busy ? 'Verifying connection…' : 'Allow app access and verify'}</button>
          <button className="secondary" disabled={busy} onClick={async () => {
            await chrome.storage.local.remove('pendingConnection'); setPendingConnection(null); setError('');
          }}>Use different pairing details</button>
        </>
      ) : !config ? (
        <>
          <CloudConnect onConnected={connection=>{setConfig(connection);setPendingConnection(null);setNotice('Cloud vault connected. Unlock below.');}}/>
          <details><summary>Advanced · manual or local connection</summary><h2>Pair your private vault</h2>
          <p>
            In the dashboard, open Browser & devices and create a scoped
            companion token.
          </p>
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setError("");
              setBusy(true);
              const f = new FormData(e.currentTarget);
              try {
                const result = await prepareConnection(chrome, f.get('origin'), f.get('token'));
                setConfig(result.connection); setPendingConnection(result.pending);
                if (result.connection) setNotice('Connection verified and saved. Unlock your vault below.');
              } catch (e) {
                reportError(e);
                const saved = await chrome.storage.local.get('pendingConnection');
                setPendingConnection(saved.pendingConnection || null);
              } finally {
                setBusy(false);
              }
            }}
          >
            <label>
              App origin
              <input
                name="origin"
                type="url"
                defaultValue="http://127.0.0.1:8110"
                autoComplete="off"
                required
              />
            </label>
            <label>
              Companion token
              <input name="token" type="password" autoComplete="off" required />
            </label>
            <button disabled={busy}>{busy ? 'Preparing connection…' : 'Pair companion'}</button>
          </form>
          <p className="fine">
            The token grants access only to your encrypted vault. Unlock keys
            are never saved. This prototype requires independent review before
            valuable credentials are stored.
          </p>
          </details>
        </>
      ) : reconnectRequired ? (
        <>
          <h2>Reconnect your vault</h2>
          <p>This connection cannot access the encrypted vault. A master passphrase cannot renew it.</p>
          <p>In Browser &amp; devices, create a scoped token for the vault you intend to use. Then enter it here. Your encrypted vault is unchanged.</p>
          <button onClick={reconnect}>Enter a new pairing token</button>
        </>
      ) : entries === null ? (
        <>
          <h2>Unlock your vault</h2>
          <p>{config.origin}</p>
          {capture && (
            <p className="notice">
              A save request from {capture.origin} is waiting. Unlock to review
              it.
            </p>
          )}
          <form onSubmit={open}>
            <label>
              {config.vaultKind==='shared'?'Sharing passphrase':'Master passphrase'}
              <input
                name="master"
                type="password"
                autoComplete="off"
                minLength={15}
                maxLength={256}
                required
              />
            </label>
            {config.vaultKind==='shared' && !config.ownerIsSelf && <><p className="fine">Verify this vault owner's fingerprint through a trusted channel. The directory alone cannot authenticate it.</p><code className="fingerprint">{config.ownerFingerprint}</code><label>Verified owner fingerprint<input name="fingerprint" autoComplete="off" pattern="[a-fA-F0-9]{64}" maxLength={64} required/></label></>}
            <button disabled={busy}>
              {busy ? "Unlocking locally…" : "Unlock"}
            </button>
          </form>
        </>
      ) : (
        <>
          <p><strong>{vaultPolicy?.name || 'Personal vault'}</strong></p>
          <div className="row">
            <span className="badge">Unlocked · this popup only</span>
            <button
              className="secondary"
              onClick={() => {
                lockVault();
              }}
            >
              Lock
            </button>
          </div>
          {capture && (
            <section>
              <h2>Review save request</h2>
              <p>
                <strong>{capture.origin}</strong>
              </p>
              <p>Username: {capture.username || "(not detected)"}</p>
              <p className="fine">
                Save only if this is the intended website. Captured values are
                not persisted until you approve.
              </p>
              <button
                disabled={busy || Date.now() > capture.expires || vaultPolicy?.browser_save===false}
                onClick={() => saveEntry(capture,update)}
              >
                {update?'Website accepted it — replace saved login':'Encrypt and save'}
              </button>
              {update && <p className="fine">Confirm the website accepted the new password before replacing this saved account.</p>}
              <button className="secondary" onClick={() => {setCapture(null);setUpdate(false);}}>
                Discard
              </button>
            </section>
          )}
          <VaultHealth entries={entries} session={session.current} browser={chrome} onApproved={approvedAction} onVaultChanged={()=>{setEntries(session.current.entries);setRevision(session.current.revision);}}/>
          <ActionQueue session={session.current} browser={chrome} refresh={actionRefresh} autoAction={autoAction} onChange={()=>{if(session.current.entries){setEntries(session.current.entries);setRevision(session.current.revision);}}}/>
          <h2>This website</h2>
          <p className="fine">
            {active?.origin ||
              "Open a supported HTTPS website. Autofill is disabled here."}
          </p>
          {entries
            .filter((e) => e.type === "login" && !isArchived(e) && e.origin === active?.origin)
            .map((entry) => (
              <section key={entry.id}>
                <h3>{entry.title}</h3>
                <p>{entry.username}</p>
                <button
                  disabled={busy}
                  onClick={async () => {
                    setError("");setNotice('');setBusy(true);
                    const generation=session.current.generation;
                    const progress=text=>{if(session.current.generation===generation)setFillStatus({id:entry.id,text,error:false,pending:true});};
                    progress('Starting autofill…');
                    try {
                      const filled=await fillSavedLogin(chrome,session.current,entry.id,active,manifest.version,progress);
                      session.current.active(generation);
                      const text=filled==='login'?"Username and password filled. Review the website before submitting.":"Password filled. This form has no detected username field; review the account before submitting.";
                      setFillStatus({id:entry.id,text,error:false,pending:false});
                    } catch (e) {
                      if(session.current.generation===generation)setFillStatus({id:entry.id,text:e.message,error:true,pending:false});
                      if(e.code==='CONNECTION_INVALID' || session.current.generation!==generation)reportError(e);
                    } finally {setBusy(false);}
                  }}
                >
                  {fillStatus?.id===entry.id && fillStatus.pending?'Filling…':'Fill this login'}
                </button>
                {fillStatus?.id===entry.id&&<p className={fillStatus.error?'error':'notice'} role={fillStatus.error?'alert':'status'} aria-live="polite">{fillStatus.text}</p>}
              </section>
            ))}
          {!entries.some(
            (e) => e.type === "login" && !isArchived(e) && e.origin === active?.origin,
          ) && (
            <p className="fine">
              No saved login for this exact origin. No wildcard domain matching
              or automatic filling.
            </p>
          )}
          {vaultPolicy?.browser_save!==false && <details>
            <summary>Save a login manually</summary>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                saveEntry({...Object.fromEntries(new FormData(e.currentTarget)),expires:Date.now()+180000});
              }}
            >
              <label>
                HTTPS website origin
                <input
                  name="origin"
                  type="url"
                  defaultValue={active?.origin || ""}
                  required
                />
              </label>
              <label>
                Username
                <input name="username" maxLength={254} />
              </label>
              <label>
                Password
                <input
                  name="password"
                  type="password"
                  autoComplete="new-password"
                  maxLength={256}
                  required
                />
              </label>
              <button
                className="secondary"
                type="button"
                onClick={(e) => {
                  e.currentTarget.form.elements.password.value =
                    generatePassword();
                }}
              >
                Generate locally
              </button>
              <button disabled={busy}>Encrypt and save</button>
            </form>
          </details>}
          <h2>Authenticator codes</h2>
          {vaultPolicy?.browser_save!==false&&<AuthenticatorSetup session={session.current} active={active} disabled={busy} onUpdated={()=>{setEntries([...session.current.entries]);setRevision(session.current.revision);}}/>}
          {entries
            .filter((e) => e.type === "totp" && !isArchived(e))
            .map((entry) => (
              <section key={entry.id}>
                <div className="row">
                  <strong>{entry.title}</strong>
                  <button
                    className="secondary"
                    onClick={async () => {
                      setError('');try{const generation=session.current.generation,value = await session.current.code(entry.id);session.current.active(generation);
                      setCode({
                        id: entry.id,
                        value,
                        expires:
                          Math.ceil(Date.now() / 1000 / entry.period) *
                          entry.period *
                          1000,
                      });
                      setTimeout(() => setCode(null), 10000);
                      }catch(e){reportError(e);}
                    }}
                  >
                    Show code
                  </button>
                </div>
                {code?.id === entry.id && code.expires > Date.now() && (
                  <p className="code">{code.value}</p>
                )}
                <CodeFill entry={entry} active={active} session={session.current} onUpdated={()=>{setEntries([...session.current.entries]);setRevision(session.current.revision);}}/>
              </section>
            ))}
          <p className="fine">
            Codes are revealed on request for up to ten seconds. Filling requires
            an explicit website link and a supported single verification-code field.
            Nothing is submitted automatically.
          </p>
        </>
      )}
      {config && (
        <footer>
          <p className="fine">
            Login-attempt drafts require per-site opt-in and expire after three minutes. New-password checks
            run locally; “Save in my vault” is explicit. Closing the popup locks
            it.
          </p>
          <button
            className="secondary"
            onClick={reconnect}
          >Connect another vault</button>
          <button
            className="secondary"
            onClick={async () => {
              await chrome.storage.local.remove(["connection", "pendingConnection"]);
              const saved = await chrome.storage.local.get('connections');
              const remaining = (saved.connections || []).filter(item=>item.token!==config.token);
              await chrome.storage.local.set({connections:remaining});setConnections(remaining);
              setConfig(null);
              setPendingConnection(null);
              setEntries(null);
              session.current.lock();
              setCapture(null);
              setCode(null);
            }}
          >
            Disconnect this browser
          </button>
        </footer>
      )}
    </main>
  );
}
const root=document.getElementById('root');
if(root)createRoot(root).render(<Popup />);
