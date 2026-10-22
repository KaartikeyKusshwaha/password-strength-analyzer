import { useEffect, useState } from "react";
import { Chrome, Download, Link2, Monitor, ShieldCheck } from "lucide-react";
import { api } from "./api";
import companionManifest from '../../companion/extension/public/manifest.json';
import BrowserConnections from './BrowserConnections';
import SecurityConnections from './SecurityConnections';
import AccessConnections from './AccessConnections';
export default function Companions({ assets, refresh, canWrite, go, devices = [] }) {
  const [error, setError] = useState(""),
    [pair, setPair] = useState(null),
    [busy, setBusy] = useState(false),
    [notice, setNotice] = useState("");
  const [deviceConfig, setDeviceConfig] = useState(null);
  const [connectionRefresh,setConnectionRefresh]=useState(0);
  const [vaults, setVaults] = useState([]);
  const [sharedVaults,setSharedVaults]=useState([]),[vaultKind,setVaultKind]=useState('personal');
  useEffect(()=>{Promise.all([api('/vaults'),api('/team-vaults')]).then(([personal,shared])=>{setVaults(personal.vaults);setSharedVaults(shared.vaults);}).catch(error=>setError(error.message));},[]);
  return (
    <>
      <p className="notice">
        <ShieldCheck size={17} /> Companions run where your accounts and devices
        are. A hosted dashboard cannot inspect your computer’s ports or see
        password forms in unrelated websites without an installed companion.
      </p>
      {error && (
        <div className="notice error" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <div className="notice" role="status">
          {notice}
        </div>
      )}
      <SecurityConnections/>
      <AccessConnections/>
      <div className="two-col">
        <section className="panel">
          <span className="tool-icon blue">
            <Chrome size={26} />
          </span>
          <h2>Browser companion</h2>
          <p>
            On supported signup and password-change forms, SentinelOps opens a password assistant automatically. Generate, evaluate and save a login in place; encrypted data syncs with your dashboard.
          </p>
          <ol className="fine">
            <li>Download and unzip the companion.</li>
            <li>
              Open your Chromium browser’s extensions page, enable developer
              mode, and choose “Load unpacked” for the unzipped folder. Review
              site access permissions.
            </li>
            <li>
              In the extension, choose “Sign in and connect.” Sign in here,
              compare the short code and approve one initialized personal or accepted shared vault.
              Reopen the extension to finish automatically. Manual tokens below
              remain available under Advanced for local installations.
            </li>
            <li>
              Unlock with your separate personal master or sharing passphrase.
              Shared vaults also require verifying the owner's fingerprint.
              No unlock key is saved.
            </li>
          </ol>
          <a
            className="button secondary"
            href="/api/downloads/browser-companion"
            download
          >
            <Download size={15} />
            Download companion
          </a>
          <p className="fine">
            Chromium 127+ prototype; not yet published to an extension store.
            Version {companionManifest.version} includes the in-page assistant, private encrypted saving and personal or shared vault connections. Reload the extension after an update. New-password detection works with standard DOM fields and selected
            naming hints. Native dialogs, cross-origin frames, closed shadow
            roots and unusual custom forms may not be detected. Your existing
            password manager remains usable.
          </p>
          <BrowserConnections refreshKey={connectionRefresh}/>
          {pair ? (
            <div className="notice">
              <h3>One-time display: pairing token</h3>
              <label>
                App origin
                <input readOnly value={pair.origin} />
              </label>
              <label>
                Scoped companion token
                <textarea readOnly rows={3} value={pair.token} />
              </label>
              <p className="fine">
                Expires in {pair.expires_days} days. Access: {pair.kind==='shared'?'one shared vault plus your encrypted sharing identity':'one encrypted personal vault'} “{pair.vault_name}”. Keep it private. Creating this token does not
                confirm pairing; the companion must show “Unlock your vault.”
              </p>
              <button
                className="button secondary"
                onClick={() => setPair(null)}
              >
                Hide token
              </button>
            </div>
          ) : (
            <details>
              <summary>Create a private connection</summary>
              <form
                onSubmit={async (e) => {
                  e.preventDefault();
                  setBusy(true);
                  setError("");
                  const form = e.currentTarget;
                  try {
                    setPair(
                      await api(
                        "/companions",
                        Object.fromEntries(new FormData(form)),
                      ),
                    );
                    form.reset();
                    setConnectionRefresh(value=>value+1);
                  } catch (e) {
                    setError(e.message);
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                <label>Connection type<select name="kind" value={vaultKind} onChange={event=>setVaultKind(event.target.value)}><option value="personal">Personal vault</option><option value="shared">Shared workspace vault</option></select></label>
                <label>Vault for this browser connection<select key={vaultKind} name="vault_id" required>{(vaultKind==='shared'?sharedVaults.filter(v=>v.accepted && v.browser_enabled):vaults.filter(v=>!v.archived && v.browser_enabled)).map(v=><option key={v.id} value={v.id}>{v.name} · {v.role || v.purpose}</option>)}</select></label>
                {vaultKind==='shared' && <p className="fine">Accept the invitation and create your sharing identity under Vaults first. View-only members can fill existing logins; saving requires edit access. This token also fetches your encrypted private sharing keys, which are unlocked only inside the extension.</p>}
                <label>
                  Connection name
                  <input
                    name="label"
                    required
                    maxLength={60}
                    placeholder="My personal browser"
                  />
                </label>
                <label>
                  Current app sign-in password
                  <input
                    name="password"
                    type="password"
                    autoComplete="current-password"
                    required
                    maxLength={128}
                  />
                </label>
                <label>
                  Unused authenticator/recovery code (if enabled)
                  <input
                    name="code"
                    autoComplete="one-time-code"
                    maxLength={80}
                  />
                </label>
                <button className="button" disabled={busy}>
                  <Link2 size={15} />
                  Create scoped token
                </button>
              </form>
            </details>
          )}
          <details>
            <summary>Revoke all browser connections</summary>
            <p className="fine">
              This disconnects every browser companion. Saved encrypted data is
              retained; unlocked companion windows may still hold plaintext
              until closed.
            </p>
            <button
              className="button secondary"
              disabled={busy}
              onClick={async () => {
                try {
                  await api("/companions/revoke", {});
                  setPair(null);
                  setConnectionRefresh(value=>value+1);
                  setNotice("All companion tokens revoked.");
                } catch (e) {
                  setError(e.message);
                }
              }}
            >
              Confirm revoke all
            </button>
          </details>
        </section>
        <section className="panel">
          <span className="tool-icon green">
            <Monitor size={26} />
          </span>
          <h2>Device companion</h2>
          <p>Start device checks in the browser extension under Check my security. Install the optional Windows helper on the computer you want to assess; a hosted website cannot inspect your computer’s ports.</p>
          <a className="button secondary" href="/api/device-helper/windows" download><Download size={15}/>Download Windows helper</a>
          <ol className="fine"><li>Open the downloaded helper and choose Install for this user. This pilot is unsigned; review its source and checksum before running.</li><li>Keep the helper window open and read its short pairing code.</li><li>In the extension, choose Connect device helper. Enter the code, compare the device and scope, then approve with your app password and MFA if enabled.</li><li>Run a device check from the extension. Progress and results appear there automatically.</li></ol>
          <p className="fine">The helper only checks its own loopback ports and the read-only posture/update checks you explicitly allow. It does not repair your OS or run arbitrary commands. Open ports are observations, not proven vulnerabilities.</p>
          <details><summary>Advanced · Python helper and manual device connections</summary>
          <p>For a separately managed Python device agent or an authorized private LAN target, create a scoped connection and run the agent yourself. Keep the process open to receive approved checks.</p>
          <button className="button secondary" onClick={() => go('overview')}>Open advanced device operator</button>
          <a className="button secondary" href="/api/downloads/device-agent" download><Download size={15}/>Download Python device agent</a>
          {deviceConfig ? <div className="notice"><h3>Private device connection ready</h3><p>Allowed targets: {deviceConfig.allowed_targets.join(', ')}. Expires in 30 days. This file contains a device credential; keep it private.</p><button className="button" onClick={()=>{const blob=new Blob([JSON.stringify(deviceConfig,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download='sentinelops-device-connection.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}}>Download private connection file</button><pre className="command-block">python sentinelops_device_agent.py --consent --connect sentinelops-device-connection.json{deviceConfig.allow_posture?' --allow-posture':''}{deviceConfig.allow_updates?' --allow-updates':''}</pre><button className="text-button" onClick={()=>setDeviceConfig(null)}>Hide connection details</button></div> : <details><summary>Create device connection</summary><form onSubmit={async event=>{event.preventDefault();setBusy(true);setError('');const form=event.currentTarget;const values=new FormData(form);try{const result=await api('/device-connections',{label:values.get('label'),password:values.get('password'),code:values.get('code'),targets:values.get('targets').split(',').map(value=>value.trim()).filter(Boolean),allow_posture:values.has('allow_posture'),allow_updates:values.has('allow_updates')});form.reset();setDeviceConfig(result);await refresh();}catch(error){setError(error.message);}finally{setBusy(false);}}}><label>Device name<input name="label" required maxLength={60} placeholder="My laptop"/></label><label>Allowed private IPs, comma separated<input name="targets" defaultValue="127.0.0.1,::1" required/></label><label className="check"><input type="checkbox" name="allow_posture"/>Allow fixed read-only Windows host posture checks (firewall, Defender and system-drive BitLocker status)</label><label className="check"><input type="checkbox" name="allow_updates"/>Allow read-only Windows Update offline-cache and update-restart status (no online search, installation or restart)</label><label>Current app sign-in password<input name="password" type="password" autoComplete="current-password" required maxLength={128}/></label><label>Unused authenticator/recovery code if enabled<input name="code" maxLength={80} autoComplete="one-time-code"/></label><button className="button" disabled={busy || !canWrite}>Create device connection</button></form></details>}
          </details>
          {devices.map(device=><div className="operation-record" key={device.id}><strong>{device.label}</strong><p className="fine">{device.seen ? 'Last seen '+new Date(device.seen*1000).toLocaleString() : 'Not connected yet'} · Scope: {device.targets.join(', ')} · Host posture: {device.allow_posture?(device.posture_enabled?'enabled by connected client':'connection granted; awaiting local consent'):'not granted'} · Update status: {device.allow_updates?(device.updates_enabled?'enabled by connected client':'connection granted; awaiting local consent'):'not granted'}</p><button className="text-button" disabled={busy || !canWrite} onClick={async()=>{setBusy(true);setError('');try{await api('/device-connections/'+device.id+'/revoke',{});if(deviceConfig?.id===device.id)setDeviceConfig(null);await refresh();}catch(e){setError(e.message);}finally{setBusy(false);}}}>Revoke this device connection</button></div>)}
        </section>
      </div>
    </>
  );
}
