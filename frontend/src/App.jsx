import React, {
  Suspense,
  lazy,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  Bell,
  Bot,
  Check,
  CheckCheck,
  ChevronDown,
  ChevronRight,
  CircleDot,
  ClipboardCheck,
  FileCode2,
  Fingerprint,
  FlaskConical,
  Globe,
  LayoutDashboard,
  ListFilter,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  MailWarning,
  Menu,
  Network,
  Plus,
  Radar,
  ScanLine,
  Search,
  Settings2,
  Shield,
  ShieldCheck,
  Sparkles,
  Terminal,
  Users,
  X,
} from "lucide-react";
import { api } from "./api";
import DevicePosture from "./DevicePosture";
import PortCoverage from "./PortCoverage";
import {version as productVersion} from '../package.json';
import WatchIndicator from "./WatchIndicator";
import ConnectionStatus from './ConnectionStatus';
import Passkeys,{PasskeySignIn} from './Passkeys';
import {performPasskey} from './passkey-client';
import "./style.css";

const ControlCenter = lazy(() => import("./ControlCenter"));
const Vault = lazy(() => import("./VaultCollection"));
const Companions = lazy(() => import("./Companions"));
const Watches = lazy(() => import("./Watches"));
const navigation = [
  ["overview", "Control center", LayoutDashboard],
  ["assets", "Asset inventory", Network],
  ["scans", "Security checks", ScanLine],
  ["findings", "Findings", Radar],
  ["tasks", "Remediation", ClipboardCheck],
  ["investigations", "Investigations", Search],
  ["agents", "Agent desk", Bot],
  ["watches", "Watches & alerts", Bell],
  ["vault", "Vault & authenticator", LockKeyhole],
  ["companions", "Browser & devices", Globe],
  ["reports", "Evidence & activity", Activity],
  ["settings", "Team & security", Settings2],
];
const titles = {
  watches: ["Keep watch as your software changes.", "Approved dependency checks, durable alerts and assigned follow-up work."],
  vault: [
    "Your accounts, under your control.",
    "Personal encrypted logins and authenticator codes, separate from team evidence.",
  ],
  companions: [
    "Security where you need it.",
    "Connect your browser and inspect your own device with explicit consent.",
  ],
  overview: [
    "Your security, handled.",
    "Connected operators. Your accounts, devices and evidence in one place.",
  ],
  assets: [
    "Know what you protect.",
    "Applications, websites and inboxes with clear ownership.",
  ],
  scans: [
    "Look closer. Act earlier.",
    "Focused checks with explicit coverage and evidence.",
  ],
  findings: [
    "Evidence before urgency.",
    "Review observations, understand context and assign the next step.",
  ],
  tasks: [
    "Close the loop.",
    "A change, supporting evidence and an independent review.",
  ],
  investigations: [
    "Connect the signals.",
    "Keep related observations and decisions in one case.",
  ],
  agents: [
    "Extra hands. Your judgment.",
    "Run evidence-based workflows, dispatch approved work, and track verification.",
  ],
  password: [
    "Better secrets start here.",
    "Private strength estimates and optional breach checks.",
  ],
  reports: [
    "A record you can review.",
    "Export observations, decisions and the linked activity trail.",
  ],
  settings: [
    "Build a trusted workspace.",
    "Manage team access, integrations and account protection.",
  ],
};
const time = (value) =>
  value
    ? new Date(value).toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "—";
const human = (value) => value?.replaceAll("_", " ") || "—";
const eventLabel = (value) => value === "companion.paired" ? "companion.token_created" : value;
function Badge({ value, children }) {
  return <span className={"badge " + value}>{children || human(value)}</span>;
}
function Empty({ title, text, action }) {
  return (
    <div className="empty">
      <div className="empty-icon">
        <Radar size={27} />
      </div>
      <h3>{title}</h3>
      <p>{text}</p>
      {action}
    </div>
  );
}
function Button({ children, onClick, secondary, ...props }) {
  return (
    <button
      className={"button" + (secondary ? " secondary" : "")}
      onClick={onClick}
      {...props}
    >
      {children}
    </button>
  );
}
function Modal({ title, close, children }) {
  const box = useRef(null);
  useEffect(() => {
    const prior = document.activeElement;
    box.current?.querySelector("input,select,textarea,button")?.focus();
    function keys(e) {
      if (e.key === "Escape") close();
      if (e.key === "Tab") {
        const items = [
          ...box.current.querySelectorAll(
            "input,select,textarea,button,a[href]",
          ),
        ].filter((el) => !el.disabled);
        if (e.shiftKey && document.activeElement === items[0]) {
          e.preventDefault();
          items.at(-1)?.focus();
        } else if (!e.shiftKey && document.activeElement === items.at(-1)) {
          e.preventDefault();
          items[0]?.focus();
        }
      }
    }
    document.addEventListener("keydown", keys);
    return () => {
      document.removeEventListener("keydown", keys);
      prior?.focus();
    };
  }, [close]);
  return (
    <div className="overlay">
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        ref={box}
      >
        <div className="panel-heading">
          <h2>{title}</h2>
          <button
            className="icon-button"
            aria-label="Close dialog"
            onClick={close}
          >
            <X />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
function Field({ label, children, ...props }) {
  return (
    <label>
      {label}
      {children || <input {...props} />}
    </label>
  );
}
function Brand() {
  return (
    <div className="brand">
      <div className="brand-mark">
        <Shield size={25} strokeWidth={1.6} />
        <i />
      </div>
      <div>
        Sentinel<span>Ops</span>
        <small>SECURITY WORKSPACE</small>
      </div>
    </div>
  );
}

export function Auth({ setup, onDone }) {
  const [mode, setMode] = useState(setup ? "setup" : "login");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [passkeyPhase,setPasskeyPhase]=useState('');
  const passkeyController=useRef(null);
  useEffect(()=>()=>passkeyController.current?.abort(),[]);
  async function passkeySignIn(event){
    const email=event.currentTarget.form.elements.email;
    if(!email.reportValidity())return;
    setBusy(true);setError('');const controller=new AbortController();passkeyController.current=controller;
    try {const result=await performPasskey('login',{email:email.value,signal:controller.signal,onPhase:setPasskeyPhase});if(result.mfa_required)setMode('factor');else await onDone();}
    catch(error){setError(error.message);}
    finally {passkeyController.current=null;setBusy(false);setPasskeyPhase('');}
  }
  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    const fields = Object.fromEntries(new FormData(e.currentTarget));
    try {
      const result = await api(
        mode === "factor" ? "/login/factor" : "/" + mode,
        fields,
      );
      if (result.mfa_required) setMode("factor");
      else await onDone();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="auth-layout">
      <aside className="auth-story">
        <Brand />
        <div>
          <span className="eyebrow">A CLEARER WAY TO SECURE YOUR TEAM</span>
          <h1>
            From scattered
            <br />
            signals to
            <br />
            <em>confident action.</em>
          </h1>
          <p>
            Bring phishing triage, exposure checks and reviewed remediation into
            one deliberate workflow.
          </p>
          <div className="auth-route">
            <ScanLine />
            <span>Observe</span>
            <i />
            <Radar />
            <span>Investigate</span>
            <i />
            <CheckCheck />
            <span>Resolve</span>
          </div>
        </div>
        <p className="auth-footer">
          Built for small teams. Designed around evidence.
        </p>
      </aside>
      <main className="auth-form">
        <div className="auth-card">
          <span className="eyebrow">SENTINELOPS / ACCESS</span>
          <h2>
            {mode === "setup"
              ? "Create your workspace"
              : mode === "join"
                ? "Join your team"
                : mode === "factor"
                  ? "One more check"
                  : "Welcome back."}
          </h2>
          <p className="muted">
            {mode === "setup"
              ? "Your first owner account. Keep its credentials private."
              : mode === "factor"
                ? "Enter an unused authenticator code or recovery code."
                : "A focused place for your team’s security work."}
          </p>
          <form onSubmit={submit} key={mode}>
            {mode === "factor" ? (
              <Field
                label="Authenticator or recovery code"
                name="code"
                autoComplete="one-time-code"
                required
                maxLength={80}
              />
            ) : (
              <>
                {(mode === "setup" || mode === "join") && (
                  <Field
                    label={
                      mode === "setup" ? "Bootstrap key" : "Invitation token"
                    }
                    name="token"
                    type="password"
                    autoComplete="off"
                    required
                  />
                )}
                {mode === "setup" && (
                  <Field
                    label="Workspace name"
                    name="workspace_name"
                    defaultValue="My security workspace"
                    minLength={2}
                    maxLength={70}
                    required
                  />
                )}
                <Field
                  label="Email address"
                  name="email"
                  type="email"
                  autoComplete="username"
                  disabled={busy}
                  required
                  maxLength={254}
                />
                <Field
                  label="Password"
                  name="password"
                  type="password"
                  disabled={busy}
                  autoComplete={
                    mode === "login" ? "current-password" : "new-password"
                  }
                  minLength={mode === "login" ? 1 : 15}
                  maxLength={128}
                  required
                />
                {mode !== "login" && (
                  <p className="fine">
                    Use 15–128 characters and an unpredictable phrase or a
                    password manager.
                  </p>
                )}
                {mode === "join" && (
                  <Field
                    label="Authenticator code (existing MFA accounts)"
                    name="code"
                    autoComplete="one-time-code"
                    maxLength={80}
                  />
                )}
              </>
            )}
            {error && (
              <div className="notice error" role="alert">
                {error}
              </div>
            )}
            <Button type="submit" disabled={busy}>
              {busy ? (
                <LoaderCircle className="spin" size={17} />
              ) : (
                <ArrowRight size={17} />
              )}{" "}
              {mode === "setup"
                ? "Create workspace"
                : mode === "join"
                  ? "Accept invitation"
                  : mode === "factor"
                    ? "Verify and continue"
                    : "Sign in"}
            </Button>
            {mode==='login' && <PasskeySignIn disabled={busy} onClick={passkeySignIn}/>}
            {busy && passkeyPhase && <p className="fine" role="status">{passkeyPhase==='requesting'?'Requesting a secure passkey challenge…':passkeyPhase==='authenticator'?'Complete the Windows or browser passkey prompt. This request expires within two minutes.':'Verifying your passkey…'}</p>}
            {busy && passkeyPhase && passkeyPhase!=='finishing' && <button type="button" className="text-button" onClick={()=>passkeyController.current?.abort()}>Cancel passkey request</button>}
          </form>
          {mode === "setup" ? (
            <p className="fine">
              The bootstrap key is in <code>data/.bootstrap-token</code> on the
              server. It is deleted after setup.
            </p>
          ) : (
            mode !== "factor" && (
              <button
                className="text-button"
                disabled={busy}
                onClick={() => {
                  setMode(mode === "join" ? "login" : "join");
                  setError("");
                }}
              >
                {mode === "join"
                  ? "Back to sign in"
                  : "Have a team invitation?"}
              </button>
            )
          )}
        </div>
      </main>
    </div>
  );
}

export default function App() {
  const [me, setMe] = useState(null);
  const [data, setData] = useState(null);
  const [setup, setSetup] = useState(false);
  const [ready, setReady] = useState(false);
  const [page, setPage] = useState("overview");
  const [vaultMode,setVaultMode]=useState('personal');
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "instant" });
  }, [page]);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [busy, setBusy] = useState(false);
  const [modal, setModal] = useState(null);
  const [selection, setSelection] = useState([]);
  const [filter, setFilter] = useState("open");
  const [query, setQuery] = useState("");
  const [mobile, setMobile] = useState(false);
  const mobileMenuButton = useRef(null);
  const [detail, setDetail] = useState(null);
  const [privateResult, setPrivateResult] = useState(null);
  const close = useCallback(() => {
    setModal(null);
    setPrivateResult(null);
  }, []);
  const refresh = useCallback(async () => {
    try {
      const user = await api("/me");
      setMe(user);
      setData(await api("/workspace"));
      setError("");
    } catch (e) {
      if (e.status === 401) {
        setMe(null);
        setData(null);
      } else throw e;
    }
  }, []);
  useEffect(() => {
    (async () => {
      try {
        setSetup((await api("/status")).setup_required);
        await refresh();
      } catch (e) {
        setError(e.message);
      } finally {
        setReady(true);
      }
    })();
  }, [refresh]);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(""), 6000);
    return () => clearTimeout(timer);
  }, [toast]);
  const running = data?.jobs.some((job) => ["queued", "running"].includes(job.status)) || data?.operations?.some(operation => ["queued", "running"].includes(operation.status));
  useEffect(() => {
    if (!running) return;
    const timer = setInterval(
      () => refresh().catch((e) => setError(e.message)),
      2500,
    );
    return () => clearInterval(timer);
  }, [running, refresh]);
  async function act(path, body, message, then) {
    setBusy(true);
    setError("");
    try {
      const result = await api(path, body);
      if (then) await then(result);
      await refresh();
      if (message) setToast(message);
      return result;
    } catch (e) {
      setError(e.message);
      return null;
    } finally {
      setBusy(false);
    }
  }
  function go(value) {
    // Background watches update their own view. Refresh the shared snapshot
    // when navigating so findings and linked work reflect the completed check.
    refresh().catch(e=>setError(e.message));
    setVaultMode(value==='shared-vaults'?'team':'personal');
    setPage(value==='shared-vaults'?'vault':value);
    setDetail(null);
    setMobile(false);
    setQuery("");
  }
  if (!ready)
    return (
      <div className="loading">
        <LoaderCircle className="spin" />
        <p>Opening your workspace…</p>
      </div>
    );
  if (!me)
    return (
      <>
        {error && (
          <div className="global-error" role="alert">
            {error}
            <button onClick={() => window.location.reload()}>Retry</button>
          </div>
        )}
        <Auth setup={setup} onDone={refresh} />
      </>
    );
  if (!data)
    return (
      <div className="loading">
        Loading workspace…{error && <p role="alert">{error}</p>}
        <Button onClick={refresh}>Retry</Button>
      </div>
    );
  const workspace = me.workspaces.find((w) => w.id === me.workspace);
  const write = me.role !== "viewer";
  const review = ["owner", "reviewer"].includes(me.role);
  const open = data.findings.filter((f) => f.status === "open");
  const unresolved = data.tasks.filter((t) => t.status !== "resolved");
  const high = open.filter((f) => ["critical", "high"].includes(f.severity));
  const assetName = (id) =>
    data.assets.find((a) => a.id === id)?.name || "Asset unavailable";
  const memberName = (id) =>
    data.members.find((m) => m.id === id)?.email || "Former member";
  const selected = selection.filter((id) =>
    data.findings.some((f) => f.id === id && f.status === "open"),
  );
  const visibleFindings = data.findings.filter(
    (f) =>
      (filter === "all" || f.status === filter || f.severity === filter) &&
      [f.title, assetName(f.asset_id), f.rule]
        .join(" ")
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  function findingRows(findings, compact = false) {
    return findings.length ? (
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              {!compact && <th aria-label="Select findings" />}
              <th>Finding / asset</th>
              <th>Severity</th>
              {!compact && <th>Evidence</th>}
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id}>
                {!compact && (
                  <td>
                    <input
                      type="checkbox"
                      aria-label={"Select " + f.title}
                      checked={selected.includes(f.id)}
                      onChange={(e) =>
                        setSelection(
                          e.target.checked
                            ? [...selected, f.id]
                            : selected.filter((id) => id !== f.id),
                        )
                      }
                    />
                  </td>
                )}
                <td>
                  <button
                    className="row-title"
                    onClick={() => {
                      setDetail(f.id);
                      setPage("findings");
                    }}
                  >
                    {f.title}
                  </button>
                  <small>
                    {assetName(f.asset_id)}{" "}
                    <span className="dot-separator">·</span> {f.rule}
                  </small>
                </td>
                <td>
                  <Badge value={f.severity} />
                </td>
                {!compact && (
                  <td>
                    <span className="mono">
                      {f.line ? "Line " + f.line : f.advisory || human(f.kind)}
                    </span>
                    <small>{f.confidence} confidence</small>
                  </td>
                )}
                <td>
                  <Badge value={f.status} />
                </td>
                <td>
                  <button
                    className="icon-button"
                    aria-label={"Open " + f.title}
                    onClick={() => {
                      setDetail(f.id);
                      setPage("findings");
                    }}
                  >
                    <ChevronRight size={17} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    ) : (
      <Empty
        title="No findings in this view"
        text={
          data.scans.length
            ? "Adjust the filter or run another focused check. A clean check is limited to its stated coverage."
            : "Add an asset and run a check to build your evidence trail."
        }
        action={
          <Button secondary onClick={() => go("scans")}>
            Open security checks <ArrowRight size={15} />
          </Button>
        }
      />
    );
  }

  const activeFinding = data.findings.find((f) => f.id === detail);
  return (
    <div className="app-shell">
      <aside id="workspace-navigation" className={"sidebar" + (mobile ? " visible" : "")} onKeyDown={event=>{
        if(event.key==='Escape' && mobile){event.preventDefault();setMobile(false);mobileMenuButton.current?.focus();}
      }}>
        <Brand />
        <div className="workspace-switch">
          <span className="workspace-avatar">
            <ShieldCheck size={19} />
          </span>
          <select
            aria-label="Switch workspace"
            value={me.workspace}
            onChange={(e) => {
              setSelection([]);
              setDetail(null);
              act(
                "/workspaces/" + e.target.value + "/switch",
                {},
                "Workspace switched",
              );
            }}
          >
            {me.workspaces.map((w) => (
              <option value={w.id} key={w.id}>
                {w.name}
              </option>
            ))}
          </select>
          <ChevronDown size={14} />
        </div>
        <span className="nav-label">WORKSPACE</span>
        <nav>
          {navigation.map(([id, label, Icon]) => (
            <button
              key={id}
              className={page === id ? "active" : ""}
              onClick={() => go(id)}
            >
              <Icon size={18} />
              <span>{label}</span>
              {id === "findings" && !!open.length && <b>{open.length}</b>}
              {id === "agents" && <i className="nav-ai">AI</i>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="agent-status">
            <span
              className={
                "status-light" +
                (data.integrations.groq_configured ? " on" : "")
              }
            />
            <div>
              <strong>
                {data.integrations.groq_configured
                  ? "Agent provider configured"
                  : "Connect your AI provider"}
              </strong>
              <small>
                {data.integrations.groq_configured
                  ? "Scoped execution"
                  : "Optional · Groq API"}
              </small>
            </div>
          </div>
          <button className="profile" onClick={() => go("settings")}>
            <span className="avatar">{me.email[0].toUpperCase()}</span>
            <span>
              <strong>{me.email.split("@")[0]}</strong>
              <small>{human(me.role)}</small>
            </span>
            <Settings2 size={16} />
          </button>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="inline">
            <button
              className="icon-button mobile-menu"
              aria-label="Toggle navigation"
              aria-expanded={mobile}
              aria-controls="workspace-navigation"
              ref={mobileMenuButton}
              onClick={() => setMobile(!mobile)}
            >
              <Menu />
            </button>
            <Shield size={16} />
            <span>Workspace</span>
            <ChevronRight size={13} />
            <strong>{navigation.find((n) => n[0] === page)?.[1]}</strong>
          </div>
          <div className="inline">
            <ConnectionStatus/>
            <WatchIndicator open={()=>go('watches')}/>
            <button
              className="icon-button"
              aria-label="Sign out"
              onClick={() => act("/logout", {}, "")}
            >
              <LogOut size={17} />
            </button>
          </div>
        </header>
        <main>
          <div className="page-heading">
            <div>
              <div className="eyebrow">
                YOUR PERSONAL SECURITY OPERATIONS
              </div>
              <h1>{titles[page][0]}</h1>
              <p>{titles[page][1]}</p>
            </div>
            <div className="heading-actions">
              {write && (
                <>
                  <Button secondary onClick={() => setModal("asset")}>
                    <Plus size={16} />
                    Add asset
                  </Button>
                  <Button onClick={() => go("scans")}>
                    <ScanLine size={16} />
                    Run a check
                  </Button>
                </>
              )}
            </div>
          </div>
          {error && (
            <div className="notice error" role="alert">
              {error}
              <button
                className="icon-button"
                aria-label="Dismiss error"
                onClick={() => setError("")}
              >
                <X size={17} />
              </button>
            </div>
          )}

          {page === "watches" && <Suspense fallback={<p>Opening dependency watches…</p>}><Watches canWrite={write} go={go}/></Suspense>}
          {page === "overview" && (
            <>
              <Suspense fallback={<p>Opening your control center…</p>}><ControlCenter data={data} refresh={refresh} go={go} canWrite={write} /></Suspense>
              <div className="metric-grid">
                {[
                  [
                    Network,
                    "Protected inventory",
                    data.assets.length,
                    "Assets registered",
                    "blue",
                  ],
                  [
                    Radar,
                    "Open findings",
                    open.length,
                    `${high.length} high or critical`,
                    "orange",
                  ],
                  [
                    ClipboardCheck,
                    "In the work queue",
                    unresolved.length,
                    `${data.tasks.filter((t) => t.status === "pending_review").length} awaiting review`,
                    "purple",
                  ],
                  [
                    CheckCheck,
                    "Reviewed resolutions",
                    data.tasks.filter((t) => t.status === "resolved").length,
                    "Human-reviewed tasks",
                    "green",
                  ],
                ].map(([Icon, label, count, note, color]) => (
                  <section className="metric" key={label}>
                    <div className="metric-label">
                      {label}
                      <span className={"metric-icon " + color}>
                        <Icon size={18} />
                      </span>
                    </div>
                    <strong>{count.toString().padStart(2, "0")}</strong>
                    <small>{note}</small>
                  </section>
                ))}
              </div>
              <div className="overview-grid">
                <section className="panel no-pad priority-panel">
                  <div className="panel-heading padded">
                    <div>
                      <span className="eyebrow">YOUR NEXT MOVES</span>
                      <h2>Priority inbox</h2>
                    </div>
                    <button
                      className="text-button"
                      onClick={() => go("findings")}
                    >
                      All findings <ArrowRight size={14} />
                    </button>
                  </div>
                  {findingRows(
                    [...open]
                      .sort(
                        (a, b) =>
                          [
                            "critical",
                            "high",
                            "medium",
                            "low",
                            "unknown",
                          ].indexOf(a.severity) -
                          [
                            "critical",
                            "high",
                            "medium",
                            "low",
                            "unknown",
                          ].indexOf(b.severity),
                      )
                      .slice(0, 5),
                    true,
                  )}
                </section>
                <section className="panel exposure-panel">
                  <div className="panel-heading">
                    <h2>Exposure breakdown</h2>
                    <Radar size={18} />
                  </div>
                  <p className="muted">
                    Open observations by reported severity
                  </p>
                  <div className="severity-bars">
                    {["critical", "high", "medium", "low", "unknown"].map(
                      (s) => (
                        <div className="severity-row" key={s}>
                          <span>
                            <i className={"severity-dot " + s} />
                            {human(s)}
                          </span>
                          <div className="bar-track">
                            <meter
                              min="0"
                              max={Math.max(1, open.length)}
                              value={
                                open.filter((f) => f.severity === s).length
                              }
                              aria-label={s + " findings"}
                            />
                          </div>
                          <b>{open.filter((f) => f.severity === s).length}</b>
                        </div>
                      ),
                    )}
                  </div>
                  <div className="fine callout">
                    <ShieldCheck size={19} />
                    <span>
                      No synthetic risk score. Severity is an observation to
                      review alongside asset context.
                    </span>
                  </div>
                </section>
              </div>
              <div className="section-heading">
                <div>
                  <span className="eyebrow">
                    ONE WORKSPACE, CONNECTED SIGNALS
                  </span>
                  <h2>A place to start</h2>
                </div>
                <span className="muted">Focused checks. Clear limits.</span>
              </div>
              <div className="tool-grid">
                {[
                  [
                    MailWarning,
                    "Phishing triage",
                    "Spot credential lures and suspicious link patterns.",
                    "email",
                    "amber",
                  ],
                  [
                    Globe,
                    "Website exposure",
                    "Assess HTTPS response headers on approved hosts.",
                    "website",
                    "blue",
                  ],
                  [
                    FileCode2,
                    "Code & dependencies",
                    "Review Python patterns and live OSV advisories.",
                    "python",
                    "purple",
                  ],
                ].map(([Icon, title, text, type, color]) => (
                  <button
                    className="tool-card"
                    key={type}
                    onClick={() => {
                      go("scans");
                      setModal(null);
                    }}
                  >
                    <span className={"tool-icon " + color}>
                      <Icon size={23} />
                    </span>
                    <h3>{title}</h3>
                    <p>{text}</p>
                    <span className="tool-link">
                      Open security checks <ArrowRight size={15} />
                    </span>
                  </button>
                ))}
              </div>
              <section className="panel activity-strip">
                <div>
                  <span className="eyebrow">LATEST ACTIVITY</span>
                  <h2>A traceable next step</h2>
                </div>
                {data.audit.events.length ? (
                  data.audit.events
                    .slice(-3)
                    .reverse()
                    .map((event) => (
                      <div className="activity-item" key={event.seq}>
                        <CircleDot size={17} />
                        <div>
                          <strong>
                            {human(eventLabel(event.action).replace(".", " · "))}
                          </strong>
                          <small>{time(event.at)}</small>
                        </div>
                      </div>
                    ))
                ) : (
                  <p className="muted">
                    Your team’s work appears here as you go.
                  </p>
                )}
                <button
                  className="icon-button"
                  aria-label="Open activity"
                  onClick={() => go("reports")}
                >
                  <ArrowRight />
                </button>
              </section>
            </>
          )}

          {page === "assets" && (
            <section className="panel no-pad">
              <div className="panel-heading padded">
                <h2>
                  Asset inventory{" "}
                  <span className="count">{data.assets.length}</span>
                </h2>
                {write && (
                  <Button secondary onClick={() => setModal("asset")}>
                    <Plus size={15} />
                    Register asset
                  </Button>
                )}
              </div>
              {data.assets.length ? (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Asset</th>
                        <th>Owner</th>
                        <th>Environment</th>
                        <th>Criticality</th>
                        <th>Open findings</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.assets.map((a) => (
                        <tr key={a.id}>
                          <td>
                            <strong>{a.name}</strong>
                            <small>{a.hostname || human(a.kind)}</small>
                          </td>
                          <td>{a.owner}</td>
                          <td>
                            <Badge value={a.environment} />
                          </td>
                          <td>
                            <Badge value={a.criticality} />
                          </td>
                          <td>
                            {open.filter((f) => f.asset_id === a.id).length}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Empty
                  title="Start with an asset you operate"
                  text="Give each application, website or team inbox an owner and environment."
                  action={
                    write && (
                      <Button onClick={() => setModal("asset")}>
                        <Plus size={15} />
                        Add first asset
                      </Button>
                    )
                  }
                />
              )}
            </section>
          )}

          {page === "scans" && (
            <div className="scan-layout">
              <section className="panel">
                <div className="panel-heading">
                  <h2>New security check</h2>
                  <ScanLine size={20} />
                </div>
                {data.assets.length ? (
                  <ScanForm
                    assets={data.assets}
                    busy={busy}
                    disabled={!write}
                    onSubmit={async (body) => {
                      const result = await act(
                        "/scans",
                        body,
                        "Check recorded with coverage details",
                      );
                      if (result) {
                        setDetail(null);
                        setPage("findings");
                      }
                    }}
                  />
                ) : (
                  <Empty
                    title="Register an asset first"
                    text="Every observation needs an accountable system or team."
                    action={
                      write && (
                        <Button onClick={() => setModal("asset")}>
                          Add asset
                        </Button>
                      )
                    }
                  />
                )}
              </section>
              <div>
                <section className="panel coverage-card">
                  <span className="eyebrow">WHAT WE CHECK</span>
                  <h2>
                    Useful signals.
                    <br />
                    Honest boundaries.
                  </h2>
                  <p>
                    Python AST patterns, exact dependency pins, selected email
                    indicators, and one HTTPS response.
                  </p>
                  <p className="muted">
                    This workspace is not a penetration test, complete code
                    audit or automated inbox filter. Submitted code and email
                    bodies are processed in memory and are not sent to AI.
                  </p>
                  <div className="inline">
                    <ShieldCheck size={18} />
                    <span>No uploaded code execution</span>
                  </div>
                </section>
                <section className="panel">
                  <h2>Recent checks</h2>
                  {data.scans.length ? (
                    data.scans.slice(0, 6).map((s) => (
                      <div className="scan-recent" key={s.id}>
                        <span className="scan-kind">
                          {s.kind === "email" ? (
                            <MailWarning size={18} />
                          ) : s.kind === "website" ? (
                            <Globe size={18} />
                          ) : (
                            <FileCode2 size={18} />
                          )}
                        </span>
                        <div>
                          <strong>{s.label}</strong>
                          <small>
                            {time(s.at)} · {s.finding_ids.length} observations
                          </small>
                        </div>
                        <Badge value={s.status} />
                      </div>
                    ))
                  ) : (
                    <p className="muted">
                      No checks have run in this workspace.
                    </p>
                  )}
                </section>
              </div>
              <section className="panel scan-history">
                <h2>Check history & coverage</h2>
                {data.scans.map((s) => (
                  <details key={s.id}>
                    <summary>
                      {s.label} · {human(s.kind)} · {s.status}{" "}
                      <span className="muted">{time(s.at)}</span>
                    </summary>
                    <p>{s.limits}</p>
                    <DevicePosture report={s.posture}/>
                    <PortCoverage observations={s.observations}/>
                    {s.error && <p className="notice error">{s.error}</p>}
                    {s.skipped?.length > 0 && (
                      <p>Not assessed: {s.skipped.join(" ")}</p>
                    )}
                    {s.packages && (
                      <p>
                        {s.checked.length}/{s.packages.length} exact pins
                        checked.
                      </p>
                    )}
                    {s.signals && <p>{s.outcome}. Raw message not retained.</p>}
                    {s.source_digest && (
                      <p className="mono wrap">
                        Submitted file SHA-256: {s.source_digest}
                      </p>
                    )}
                  </details>
                ))}
              </section>
            </div>
          )}

          {page === "findings" && (
            <>
              {activeFinding ? (
                <section className="panel finding-detail">
                  <button
                    className="text-button"
                    onClick={() => setDetail(null)}
                  >
                    ← Back to findings
                  </button>
                  <div className="section-heading">
                    <div>
                      <span className="eyebrow">
                        {activeFinding.rule} / {activeFinding.cwe}
                      </span>
                      <h2>{activeFinding.title}</h2>
                      <p className="muted">
                        {assetName(activeFinding.asset_id)} ·{" "}
                        {activeFinding.label}
                      </p>
                    </div>
                    <Badge value={activeFinding.severity} />
                  </div>
                  <div className="evidence-box">
                    <span className="eyebrow">OBSERVED EVIDENCE</span>
                    <p>{activeFinding.evidence}</p>
                    {activeFinding.advisory_ids?.length>0&&<details><summary>Advisory IDs and reported aliases ({activeFinding.advisory_ids.length})</summary><p>{activeFinding.advisory_ids.join(', ')}</p><p className="fine">Matched IDs: {activeFinding.matched_advisories.join(', ')}. Aliases describe provider relationships, not additional affected packages. Historical tasks are retained.</p></details>}
                    <small>
                      {activeFinding.line
                        ? `Line ${activeFinding.line} · `
                        : ""}
                      {activeFinding.confidence} confidence · last seen{" "}
                      {time(activeFinding.last_seen)}
                    </small>
                  </div>
                  {!activeFinding.observed_in_latest && (
                    <div className="notice">
                      Not observed in the latest check of this scope. Resolution
                      still requires evidence and review.
                    </div>
                  )}
                  <h3>Recommended next step</h3>
                  <p>{activeFinding.guidance}</p>
                  <a
                    className="text-button"
                    href={activeFinding.reference}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Read source guidance ↗
                  </a>
                  <div className="inline detail-actions">
                    <Badge value={activeFinding.status} />
                    {write && activeFinding.status === "open" && (
                      <Button
                        onClick={() =>
                          setModal({ type: "task", finding: activeFinding })
                        }
                      >
                        <Plus size={15} />
                        Assign remediation
                      </Button>
                    )}
                  </div>
                </section>
              ) : (
                <section className="panel no-pad">
                  <div className="finding-toolbar">
                    <div className="search-field">
                      <Search size={17} />
                      <input
                        aria-label="Search findings"
                        placeholder="Search findings, assets, rules…"
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                      />
                    </div>
                    <select
                      aria-label="Filter findings"
                      value={filter}
                      onChange={(e) => setFilter(e.target.value)}
                    >
                      {[
                        "open",
                        "resolved",
                        "all",
                        "critical",
                        "high",
                        "medium",
                        "low",
                        "unknown",
                      ].map((s) => (
                        <option key={s} value={s}>
                          {human(s)}
                        </option>
                      ))}
                    </select>
                    <span className="muted">{selected.length} selected</span>
                    {write && (
                      <>
                        <Button
                          secondary
                          disabled={!selected.length}
                          onClick={() => setModal("investigation")}
                        >
                          Investigate
                        </Button>
                        <Button
                          disabled={
                            !selected.length ||
                            selected.length > 20 ||
                            !data.integrations.groq_configured
                          }
                          onClick={() => {
                            setPage("agents");
                          }}
                        >
                          <Sparkles size={15} />
                          Ask agents
                        </Button>
                      </>
                    )}
                  </div>
                  {findingRows(visibleFindings)}
                </section>
              )}
            </>
          )}

          {page === "tasks" && (
            <div className="task-board">
              {["open", "in_progress", "pending_review", "resolved"].map(
                (status) => (
                  <section className="board-column" key={status}>
                    <div className="board-heading">
                      <span className={"severity-dot " + status} />
                      <h2>{human(status)}</h2>
                      <span className="count">
                        {data.tasks.filter((t) => t.status === status).length}
                      </span>
                    </div>
                    {data.tasks
                      .filter((t) => t.status === status)
                      .map((task) => (
                        <article className="task-card" key={task.id}>
                          <span className="eyebrow">
                            {task.finding_id.slice(0, 8)}
                          </span>
                          <h3>{task.title}</h3>
                          <p className="muted">{memberName(task.assignee)}</p>
                          {task.due && <small>Due {task.due}</small>}
                          {task.agent_guidance && (
                            <details>
                              <summary>Agent work instructions</summary>
                              <p>{task.agent_guidance.priority_reason}</p>
                              <ol>{task.agent_guidance.actions.map((action, i) => <li key={i}>{action}</li>)}</ol>
                              <p><strong>Verification:</strong> {task.agent_guidance.verification}</p>
                              <p className="fine">AI-generated instructions. Submit your actual change and test evidence for independent review.</p>
                            </details>
                          )}
                          {task.evidence && (
                            <details>
                              <summary>Submission evidence</summary>
                              <p>{task.evidence}</p>
                            </details>
                          )}
                          {task.review && (
                            <p className="review-note">Review: {task.review}</p>
                          )}
                          <div className="task-actions">
                            {write &&
                              task.assignee === me.id &&
                              ["open", "in_progress"].includes(status) && (
                                <>
                                  {status === "open" && (
                                    <button
                                      className="text-button"
                                      disabled={busy}
                                      onClick={() =>
                                        act(
                                          "/tasks/" + task.id,
                                          { action: "start" },
                                          "Task started",
                                        )
                                      }
                                    >
                                      Start
                                    </button>
                                  )}
                                  <Button
                                    secondary
                                    onClick={() =>
                                      setModal({
                                        type: "task-update",
                                        task,
                                        action: "submit",
                                      })
                                    }
                                  >
                                    Submit evidence
                                  </Button>
                                </>
                              )}
                            {review &&
                              status === "pending_review" &&
                              task.submitted_by !== me.id && (
                                <>
                                  <Button
                                    secondary
                                    onClick={() =>
                                      setModal({
                                        type: "task-update",
                                        task,
                                        action: "reject",
                                      })
                                    }
                                  >
                                    Request changes
                                  </Button>
                                  <Button
                                    onClick={() =>
                                      setModal({
                                        type: "task-update",
                                        task,
                                        action: "approve",
                                      })
                                    }
                                  >
                                    Review & approve
                                  </Button>
                                </>
                              )}
                            {status === "pending_review" &&
                              task.submitted_by === me.id && (
                                <p className="fine">
                                  Waiting for an independent reviewer.
                                </p>
                              )}
                          </div>
                        </article>
                      ))}
                    {!data.tasks.some((t) => t.status === status) && (
                      <div className="board-empty">No tasks here</div>
                    )}
                  </section>
                ),
              )}
            </div>
          )}

          {page === "investigations" && (
            <>
              <div className="section-heading">
                <p className="muted">
                  Link selected findings into a case; keep raw sensitive
                  material outside shared notes.
                </p>
                <Button secondary onClick={() => go("findings")}>
                  Select findings <ArrowRight size={15} />
                </Button>
              </div>
              {data.investigations.length ? (
                <div className="two-col">
                  {data.investigations.map((item) => (
                    <section className="panel" key={item.id}>
                      <div className="panel-heading">
                        <h2>{item.title}</h2>
                        <Badge value={item.status} />
                      </div>
                      <p className="muted">
                        Opened {time(item.created_at)} ·{" "}
                        {item.finding_ids.length} linked observations
                      </p>
                      {item.finding_ids.map((id) => (
                        <button
                          key={id}
                          className="linked-finding"
                          onClick={() => {
                            setDetail(id);
                            setPage("findings");
                          }}
                        >
                          <Radar size={15} />
                          {data.findings.find((f) => f.id === id)?.title}
                          <ChevronRight size={15} />
                        </button>
                      ))}
                      <div className="case-notes">
                        {item.notes.map((note, i) => (
                          <div key={i}>
                            <p>{note.text}</p>
                            <small>
                              {memberName(note.by)} · {time(note.at)}
                            </small>
                          </div>
                        ))}
                      </div>
                      {write && (
                        <Button
                          secondary
                          onClick={() =>
                            setModal({ type: "case-update", item })
                          }
                        >
                          Update investigation
                        </Button>
                      )}
                    </section>
                  ))}
                </div>
              ) : (
                <section className="panel">
                  <Empty
                    title="Build the story behind the signals"
                    text="Select related findings, open an investigation, and document the decision trail."
                    action={
                      <Button onClick={() => go("findings")}>
                        Review findings
                      </Button>
                    }
                  />
                </section>
              )}
            </>
          )}

          {page === "agents" && (
            <div className="agent-layout">
              <section className="panel agent-control">
                <span className="agent-symbol">
                  <Bot size={34} />
                </span>
                <span className="eyebrow">SECURITY WORKFLOW OPERATORS</span>
                <h2>
                  Evidence in.
                  <br />Work carried forward.
                </h2>
                <p className="muted">
                  Give a scoped objective to a coordinated workflow. An AI planner
                  works with tool workers that collect evidence, validate references,
                  dispatch authorized work, and check later scan and review results.
                </p>
                <div className="agent-flow">
                  {[
                    "Evidence collector",
                    "AI remediation planner",
                    "Citation verifier",
                    "Work dispatcher",
                    "Progress checker",
                  ].map((s, i) => (
                    <div key={s}>
                      <span>0{i + 1}</span>
                      <strong>{s}</strong>
                    </div>
                  ))}
                </div>
                <p>
                  {selected.length} selected finding
                  {selected.length !== 1 ? "s" : ""}{" "}
                  <button
                    className="text-button"
                    onClick={() => go("findings")}
                  >
                    Change selection
                  </button>
                </p>
                <form
                  onSubmit={async (e) => {
                    e.preventDefault();
                    const form = new FormData(e.currentTarget);
                    const body = {
                      finding_ids: selected,
                      mode: form.get("mode"),
                      create_tasks: form.has("create_tasks"),
                      create_investigation: form.has("create_investigation"),
                    };
                    await act("/agents", body, "Agent run queued");
                  }}
                >
                  <Field label="Objective">
                    <select name="mode">
                      <option value="triage">Prioritize and triage</option>
                      <option value="remediation">Plan remediation</option>
                      <option value="investigation">
                        Prepare investigation brief
                      </option>
                    </select>
                  </Field>
                  <label className="check"><input type="checkbox" name="create_tasks" />Create remediation tasks assigned to me; reuse existing active tasks.</label>
                  <label className="check"><input type="checkbox" name="create_investigation" />Create an investigation with the selected findings and draft brief.</label>
                  <p className="fine">These permissions apply to this run only. Leave both unchecked to prepare a plan without creating work items.</p>
                  <Button
                    type="submit"
                    disabled={
                      busy ||
                      !write ||
                      !selected.length ||
                      selected.length > 20 ||
                      !data.integrations.groq_configured
                    }
                  >
                    <Sparkles size={16} />
                    Run selected findings
                  </Button>
                </form>
                {!data.integrations.groq_configured && (
                  <div className="notice">
                    Provider not connected. Configure <code>GROQ_API_KEY</code>{" "}
                    in the server’s private .env file. No AI output is
                    simulated.
                  </div>
                )}
                <p className="fine">
                  Up to 20 open findings and one model call per run. Only IDs, rule
                  titles, severities, confidence and fixed guidance are shared
                  with Groq. Work is dispatched only if evidence is still current.
                  The workflow cannot change passwords, execute system commands,
                  or approve remediation. Progress checks use recorded results;
                  they do not run a new scan.
                </p>
              </section>
              <div className="agent-runs">
                {data.jobs.length ? (
                  data.jobs.map((job) => (
                    <section className="panel" key={job.id}>
                      <div className="panel-heading">
                        <div>
                          <span className="eyebrow">
                            {human(job.mode)} / {time(job.created_at)}
                          </span>
                          <h2>Agent run {job.id.slice(0, 6)}</h2>
                        </div>
                        <Badge value={job.status} />
                      </div>
                      {job.steps.map((step, i) => (
                        <div className="agent-step" key={i}>
                          <span className={"step-circle " + step.status}>
                            {step.status === "complete" ? (
                              <Check size={14} />
                            ) : (
                              <CircleDot size={14} />
                            )}
                          </span>
                          <div>
                            <strong>{step.agent}</strong>
                            <p>{step.detail}</p>
                          </div>
                          <Badge value={step.status} />
                        </div>
                      ))}
                      {job.error && (
                        <div className="notice error">{job.error}</div>
                      )}
                      {job.plan && (
                        <div className="agent-plan">
                          <p>{job.plan.summary}</p>
                          {job.plan.recommendations.map((r) => (
                            <div key={r.finding_id}>
                              <button
                                className="text-button"
                                onClick={() => {
                                  setPage("findings");
                                  setDetail(r.finding_id);
                                }}
                              >
                                {data.findings.find(
                                  (f) => f.id === r.finding_id,
                                )?.title || r.finding_id}{" "}
                                ↗
                              </button>
                              <p>{r.priority_reason}</p>
                              <ol>
                                {r.actions.map((a, i) => (
                                  <li key={i}>{a}</li>
                                ))}
                              </ol>
                              <p>
                                <strong>Verify:</strong> {r.verification}
                              </p>
                            </div>
                          ))}
                          <p className="fine">
                            AI-generated draft. Reference coverage verified;
                            advice correctness has not been independently
                            verified.
                          </p>
                        </div>
                      )}
                      {job.output && (
                        <div className="notice">
                          {job.output.status === "draft_only" ? "Plan prepared. Work-item creation was not authorized." : `${job.output.tasks.length} tasks created · ${job.output.reused_tasks.length} active tasks linked · ${job.output.investigation ? "1 investigation created" : "no investigation requested"}`}
                          {job.output.status !== "draft_only" && <p><button className="text-button" onClick={() => go("tasks")}>Open remediation board ↗</button>{job.output.investigation && <button className="text-button" onClick={() => go("investigations")}>Open investigations ↗</button>}</p>}
                        </div>
                      )}
                      {job.status === "complete" && <Button secondary disabled={busy || !write} onClick={() => act("/agents/" + job.id + "/progress", {}, "Progress checked against recorded evidence")}>Check progress</Button>}
                      {job.progress && (
                        <div className="agent-plan">
                          <h3>Verification progress</h3>
                          <p className="fine">Checked {time(job.progress.checked_at)}</p>
                          {job.progress.checks.map(check => <p key={check.finding_id}><strong>{data.findings.find(f => f.id === check.finding_id)?.title || check.finding_id}</strong><br />{human(check.state)}</p>)}
                          <p className="fine">{job.progress.limits}</p>
                        </div>
                      )}
                    </section>
                  ))
                ) : (
                  <section className="panel">
                    <Empty
                      title="Your agents are ready for evidence"
                      text="Select open findings, choose an objective and authorize any work-item creation. Follow execution and verification here."
                    />
                  </section>
                )}
              </div>
            </div>
          )}

          {page === "reports" && (
            <>
              <section className="panel report-hero">
                <div className="report-icon">
                  <ClipboardCheck size={34} />
                </div>
                <div>
                  <span className="eyebrow">EVIDENCE PACKAGE</span>
                  <h2>The observations. The work. The decisions.</h2>
                  <p className="muted">
                    A timestamped JSON export of this workspace with a content
                    checksum and hash-linked activity.
                  </p>
                  <p className="fine">
                    No raw source or email bodies. Notes may contain information
                    your team entered. Review before sharing.
                  </p>
                </div>
                <a className="button" href="/api/report" download>
                  <ArrowDownToLine size={16} />
                  Export evidence
                </a>
              </section>
              <section className="panel no-pad">
                <div className="panel-heading padded">
                  <h2>Activity trail</h2>
                  <Badge value={data.audit.valid ? "green" : "critical"}>
                    {data.audit.valid ? "Links verified" : "Link mismatch"}
                  </Badge>
                </div>
                <p className="padded fine">
                  Link integrity is checked on read. An administrator with
                  database access can rewrite the chain; retain exported heads
                  externally for comparison. This is not an independently signed
                  audit log.
                </p>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Action</th>
                        <th>Actor</th>
                        <th>Record</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.audit.events
                        .slice()
                        .reverse()
                        .map((event) => (
                          <tr key={event.seq}>
                            <td>{time(event.at)}</td>
                            <td>{eventLabel(event.action)}</td>
                            <td>{memberName(event.actor)}</td>
                            <td className="mono">
                              {event.target.slice(0, 16)}
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          )}

          {page === "vault" && (
            <Suspense
              fallback={<div className="loading">Loading private vault…</div>}
            >
              <Vault key={me.id+me.workspace+vaultMode} me={me} initialMode={vaultMode}/>
            </Suspense>
          )}
          {page === "companions" && (
            <Suspense
              fallback={<div className="loading">Loading companions…</div>}
            >
              <Companions
                go={go}
                devices={data.devices || []}
                assets={data.assets}
                refresh={refresh}
                canWrite={write}
              />
            </Suspense>
          )}
          {page === "settings" && (
            <div className="settings-grid">
              <Passkeys mfaEnabled={me.mfa_enabled} onSessionChanged={refresh}/>
              <section className="panel">
                <div className="panel-heading">
                  <h2>Team members</h2>
                  <Users size={20} />
                </div>
                {data.members.map((m) => (
                  <div className="member-row" key={m.id}>
                    <span className="avatar light">
                      {m.email[0].toUpperCase()}
                    </span>
                    <div>
                      <strong>{m.email}</strong>
                      <small>
                        {m.id === me.id ? "You" : "Workspace member"}
                      </small>
                    </div>
                    <Badge value={m.role} />
                    {me.role==='owner' && m.role!=='owner' && <Button secondary onClick={()=>setModal({type:'offboard',member:m})}>Remove workspace access</Button>}
                  </div>
                ))}
                {me.role === "owner" && (
                  <Button secondary onClick={() => setModal("invite")}>
                    <Plus size={15} />
                    Invite a teammate
                  </Button>
                )}
                <p className="fine">
                  Analysts work on findings. Reviewers can independently decide
                  remediation. Viewers can inspect and export. Owners manage
                  invitations.
                </p>
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <h2>Account protection</h2>
                  <LockKeyhole size={20} />
                </div>
                <div className="protection-state">
                  <span className="tool-icon green">
                    <ShieldCheck size={25} />
                  </span>
                  <div>
                    <h3>Authenticator protection</h3>
                    <Badge value={me.mfa_enabled ? "green" : "medium"}>
                      {me.mfa_enabled ? "Enabled" : "Not enabled"}
                    </Badge>
                  </div>
                </div>
                <p className="muted">
                  Time-based one-time codes, encrypted secrets at rest and
                  single-use recovery codes.
                </p>
                {me.mfa_enabled ? (
                  <>
                    <p>{me.recovery_remaining} recovery codes remain.</p>
                    <Button secondary onClick={() => setModal("mfa-disable")}>
                      Disable with reauthentication
                    </Button>
                  </>
                ) : (
                  <Button onClick={() => setModal("mfa-setup")}>
                    Set up authenticator
                  </Button>
                )}
                <p className="fine">
                  Setup and disable rotate your session and revoke your other
                  sessions. Authenticator codes cannot be replayed.
                </p>
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <h2>Connected capabilities</h2>
                  <Terminal size={20} />
                </div>
                <div className="integration">
                  <span>Groq agent provider</span>
                  <Badge
                    value={
                      data.integrations.groq_configured ? "green" : "unknown"
                    }
                  >
                    {data.integrations.groq_configured
                      ? "Configured"
                      : "Not configured"}
                  </Badge>
                </div>
                <div className="integration">
                  <span>OSV dependency advisories</span>
                  <Badge value="green">Live API</Badge>
                </div>
                <div className="integration">
                  <span>HIBP password ranges</span>
                  <Badge value="blue">Browser opt-in</Badge>
                </div>
                <div className="integration">
                  <span>Approved website hosts</span>
                  <Badge value="blue">
                    {data.integrations.scan_hosts.length}
                  </Badge>
                </div>
                <p className="fine">
                  Set SCAN_HOSTS in the server .env to exact hostnames you may
                  assess. Website requests use verified TLS and vetted public
                  IPs; redirects are not followed.
                </p>
                <p className="mono wrap">
                  {data.integrations.scan_hosts.join(", ") ||
                    "No website hosts approved yet"}
                </p>
              </section>
              <section className="panel">
                <span className="eyebrow">WORKSPACE BOUNDARIES</span>
                <h2>A separate space for each team</h2>
                <p className="muted">
                  Create an isolated workspace for another team. Your personal encrypted vault stays linked to your account.
                </p>
                <div className="inline">
                  <Button secondary onClick={() => setModal("workspace")}>
                    New workspace
                  </Button>

                </div>
                <p className="fine">
                  Pilot architecture: one Python process and SQLite. This build
                  includes opt-in dependency watches while the server runs and
                  scoped paired-device checks. Inbox sync, SSO, billing and full
                  endpoint detection/response are not implemented.
                </p>
              </section>
            </div>
          )}
          <footer className="page-footer">
            <span>
              <Shield size={13} />
              SentinelOps <b>{productVersion}</b>
            </span>
            <span>Observe thoughtfully. Resolve with evidence.</span>
          </footer>
        </main>
      </div>
      {toast && (
        <div className="toast" role="status">
          <CheckCheck size={18} />
          {toast}
        </div>
      )}
      {modal && (
        <Modal
          title={
            typeof modal === "object"
              ? modal.type === 'offboard'
                ? 'Remove workspace access'
                : modal.type === "task"
                ? "Assign remediation"
                : modal.type === "task-update"
                  ? "Reviewable evidence"
                  : "Update investigation"
              : {
                  asset: "Register an asset",
                  invite: "Invite a teammate",
                  investigation: "Open an investigation",
                  "mfa-setup": "Set up authenticator",
                  "mfa-disable": "Disable authenticator",
                  workspace: "Create workspace",
                }[modal]
          }
          close={close}
        >
          {error && (
            <div className="notice error" role="alert">
              {error}
            </div>
          )}
          {privateResult ? (
            <PrivateResult
              result={privateResult}
              onConfirm={async (body) => {
                const r = await act(
                  "/mfa/enable",
                  body,
                  "Authenticator enabled",
                );
                if (r) setPrivateResult(r);
              }}
            />
          ) : (
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                const values = Object.fromEntries(
                  new FormData(e.currentTarget),
                );
                let path,
                  body = values;
                if (modal === "asset") {
                  path = "/assets";
                  body.authorized = values.authorized === "on";
                } else if (modal === "invite") path = "/invites";
                else if (modal === "workspace") path = "/workspaces";
                else if (modal === "investigation") {
                  path = "/investigations";
                  body.finding_ids = selected;
                } else if (modal === "mfa-setup") path = "/mfa/setup";
                else if (modal === "mfa-disable") path = "/mfa/disable";
                else if (modal.type === "task") {
                  path = "/tasks";
                  body.finding_id = modal.finding.id;
                } else if (modal.type === "task-update") {
                  path = "/tasks/" + modal.task.id;
                  body.action = modal.action;
                } else if (modal.type === 'offboard') path='/members/'+modal.member.id+'/offboard';
                else if (modal.type === "case-update")
                  path = "/investigations/" + modal.item.id;
                const result = await act(path, body, modal.type==='offboard'?'Access removed. Rotate affected vault keys and known website passwords.':'Saved');
                if (result) {
                  if (["invite", "mfa-setup"].includes(modal))
                    setPrivateResult(result);
                  else {
                    close();
                    if (modal === "workspace") {
                      await act(
                        "/workspaces/" + result.id + "/switch",
                        {},
                        "Workspace ready",
                      );
                      setSelection([]);
                    }
                  }
                }
              }}
            >
              {modal.type==='offboard' && <><p>Remove {modal.member.email} from this workspace, revoke their sessions and paired devices, and stop their active jobs. Shared vault access will be revoked and affected vaults will require key rotation. Personal vaults stay with their account.</p><p>Cached credentials cannot be erased. Change website passwords the former member knew. Members who own shared vaults cannot be offboarded until ownership transfer is supported.</p><Field label="Your current sign-in password" name="password" type="password" autoComplete="current-password" required/>{me.mfa_enabled && <Field label="Unused authenticator or recovery code" name="code" autoComplete="one-time-code" required/>}</>}
              {modal === "asset" && (
                <>
                  <Field
                    label="Asset name"
                    name="name"
                    placeholder="Customer portal"
                    required
                    minLength={2}
                    maxLength={80}
                  />
                  <div className="form-grid">
                    <Field label="Asset type">
                      <select name="kind">
                        <option value="application">Application</option>
                        <option value="website">Website</option>
                        <option value="mailbox">Team inbox</option>
                        <option value="service">Service</option>
                        <option value="device">Personal device</option>
                      </select>
                    </Field>
                    <Field label="Environment">
                      <select name="environment">
                        <option value="production">Production</option>
                        <option value="staging">Staging</option>
                        <option value="development">Development</option>
                      </select>
                    </Field>
                  </div>
                  <Field
                    label="Responsible team or person"
                    name="owner"
                    required
                    minLength={2}
                    maxLength={80}
                  />
                  <Field label="Business criticality">
                    <select name="criticality">
                      {["critical", "high", "medium", "low"].map((v) => (
                        <option key={v}>{v}</option>
                      ))}
                    </select>
                  </Field>
                  <Field
                    label="Website hostname (optional)"
                    name="hostname"
                    placeholder="app.your-company.com"
                    maxLength={253}
                  />
                  <label className="check">
                    <input type="checkbox" name="authorized" required />I
                    operate this asset or have permission to assess it.
                  </label>
                </>
              )}
              {modal === "invite" && (
                <>
                  <Field
                    label="Teammate email"
                    name="email"
                    type="email"
                    required
                    maxLength={254}
                  />
                  <Field label="Role">
                    <select name="role">
                      <option value="analyst">Analyst</option>
                      <option value="reviewer">Reviewer</option>
                      <option value="viewer">Viewer</option>
                    </select>
                  </Field>
                  <p className="fine">
                    You receive a one-time token to share privately. No email is
                    sent. Expires after 24 hours.
                  </p>
                </>
              )}
              {modal === "workspace" && (
                <Field
                  label="Workspace name"
                  name="name"
                  minLength={2}
                  maxLength={70}
                  required
                />
              )}
              {modal === "investigation" && (
                <>
                  <p>{selected.length} selected findings</p>
                  <Field
                    label="Case title"
                    name="title"
                    minLength={3}
                    maxLength={120}
                    required
                  />
                  <Field label="Opening note">
                    <textarea name="note" maxLength={3000} />
                  </Field>
                </>
              )}
              {modal === "mfa-setup" && (
                <>
                  <p>
                    Re-enter your password to start a new authenticator setup.
                    Existing protection cannot be overwritten.
                  </p>
                  <Field
                    label="Current password"
                    name="password"
                    type="password"
                    autoComplete="current-password"
                    maxLength={128}
                    required
                  />
                </>
              )}
              {modal === "mfa-disable" && (
                <>
                  <Field
                    label="Current password"
                    name="password"
                    type="password"
                    autoComplete="current-password"
                    maxLength={128}
                    required
                  />
                  <Field
                    label="Unused authenticator or recovery code"
                    name="code"
                    autoComplete="one-time-code"
                    maxLength={80}
                    required
                  />
                </>
              )}
              {modal.type === "task" && (
                <>
                  <p>
                    <strong>{modal.finding.title}</strong>
                  </p>
                  <Field label="Assign to">
                    <select name="assignee">
                      {data.members
                        .filter((m) => m.role !== "viewer")
                        .map((m) => (
                          <option value={m.id} key={m.id}>
                            {m.email}
                          </option>
                        ))}
                    </select>
                  </Field>
                  <Field label="Due date (optional)" name="due" type="date" />
                  <p className="fine">
                    The person submitting work cannot approve their own
                    resolution. Invite a reviewer to close the loop.
                  </p>
                </>
              )}
              {modal.type === "task-update" && (
                <>
                  <p>{modal.task.title}</p>
                  <Field
                    label={
                      modal.action === "submit"
                        ? "What changed and how did you verify it?"
                        : "Review evidence and decision rationale"
                    }
                  >
                    <textarea
                      name="evidence"
                      minLength={15}
                      maxLength={3000}
                      required
                      rows={5}
                    />
                  </Field>
                  <p className="fine">
                    Use a commit reference, test result or trusted verification
                    record. Do not paste secrets. Approval is a documented human
                    decision, not an automated guarantee.
                  </p>
                </>
              )}
              {modal.type === "case-update" && (
                <>
                  <Field label="Status">
                    <select name="status" defaultValue={modal.item.status}>
                      <option value="open">Open</option>
                      <option value="investigating">Investigating</option>
                      {review && <option value="closed">Closed</option>}
                    </select>
                  </Field>
                  <Field label="Progress or decision note">
                    <textarea
                      name="note"
                      minLength={5}
                      maxLength={3000}
                      required
                      rows={4}
                    />
                  </Field>
                  <p className="fine">
                    Close a case after linked findings are resolved through
                    reviewed tasks.
                  </p>
                </>
              )}
              <div className="modal-actions">
                <Button secondary type="button" onClick={close}>
                  Cancel
                </Button>
                <Button type="submit" disabled={busy}>
                  {busy ? "Saving…" : "Save and continue"}
                </Button>
              </div>
            </form>
          )}
        </Modal>
      )}
    </div>
  );
}

function ScanForm({ assets, busy, disabled, onSubmit }) {
  const [kind, setKind] = useState("python");
  const [asset, setAsset] = useState(assets[0].id);
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        const body = Object.fromEntries(new FormData(e.currentTarget));
        body.authorized = body.authorized === "on";
        onSubmit(body);
      }}
    >
      <fieldset disabled={disabled || busy}>
        <Field label="Assessment type">
          <select
            name="kind"
            value={kind}
            onChange={(e) => setKind(e.target.value)}
          >
            <option value="python">Python source review</option>
            <option value="dependencies">Dependency advisories</option>
            <option value="email">Phishing triage</option>
            <option value="website">Website HTTPS headers</option>
          </select>
        </Field>
        <Field label="Asset">
          <select
            name="asset_id"
            value={asset}
            onChange={(e) => setAsset(e.target.value)}
          >
            {assets.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        </Field>
        <Field
          label="Scope / file / message reference"
          name="label"
          placeholder={
            kind === "python"
              ? "auth/reset.py"
              : kind === "email"
                ? "Reported message 001"
                : "Primary assessment"
          }
          required
          minLength={2}
          maxLength={100}
        />
        {kind === "dependencies" && (
          <Field label="Dependency format">
            <select name="format">
              <option value="requirements">
                requirements.txt (exact pins)
              </option>
              <option value="package-json">package.json (exact pins)</option>
            </select>
          </Field>
        )}
        {kind === "website" ? (
          <div className="notice">
            Hostname:{" "}
            <strong>
              {assets.find((a) => a.id === asset)?.hostname ||
                "No hostname registered"}
            </strong>
            <p>
              Requires an exact SCAN_HOSTS entry from the server operator. One
              verified HTTPS HEAD request; no redirects or exploitation.
            </p>
          </div>
        ) : (
          <Field
            label={
              kind === "email"
                ? "Message text (processed in memory)"
                : "Content to assess (processed in memory)"
            }
          >
            <textarea
              key={kind}
              name="content"
              required
              rows={12}
              maxLength={kind === "email" ? 15000 : 120000}
              spellCheck="false"
              placeholder={
                kind === "dependencies"
                  ? "requests==2.19.1\n# Ranges are reported as not assessed"
                  : kind === "python"
                    ? "Paste a Python file you may assess…"
                    : "Paste the reported message, without unnecessary personal data…"
              }
            />
          </Field>
        )}
        <label className="check">
          <input name="authorized" type="checkbox" required />I am authorized to
          assess this content or system.
        </label>
        <Button type="submit" disabled={busy || disabled}>
          {busy ? (
            <LoaderCircle className="spin" size={16} />
          ) : (
            <ScanLine size={16} />
          )}{" "}
          {busy ? "Assessing…" : "Run focused check"}
        </Button>
      </fieldset>
    </form>
  );
}

function PrivateResult({ result, onConfirm }) {
  const [error, setError] = useState("");
  if (result.token)
    return (
      <>
        <div className="notice">
          Shown once. Share this privately with the invited teammate; they
          choose “Have a team invitation?” at sign-in.
        </div>
        <label>
          Invitation token
          <textarea readOnly rows={3} value={result.token} />
        </label>
        <p>Expires in {result.expires_in_hours} hours.</p>
      </>
    );
  if (result.recovery_codes)
    return (
      <>
        <div className="notice">
          Authenticator enabled. Store these single-use recovery codes somewhere
          private. They will not be shown again.
        </div>
        <textarea
          aria-label="Recovery codes"
          className="mono"
          readOnly
          rows={9}
          value={result.recovery_codes.join("\n")}
        />
      </>
    );
  return (
    <>
      <p>
        Add a time-based account in your authenticator using this setup key.
        Setup expires in ten minutes.
      </p>
      <label>
        Setup key
        <input readOnly value={result.secret} />
      </label>
      <p className="fine">
        Issuer: SentinelOps · SHA-1 · 6 digits · 30 seconds. Keep this key
        private.
      </p>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setError("");
          try {
            await onConfirm({
              code: new FormData(e.currentTarget).get("code"),
            });
          } catch (err) {
            setError(err.message);
          }
        }}
      >
        <Field
          label="Authenticator code"
          name="code"
          autoComplete="one-time-code"
          pattern="[0-9]{6}"
          required
        />
        {error && <p role="alert">{error}</p>}
        <Button type="submit">Verify and enable</Button>
      </form>
    </>
  );
}
