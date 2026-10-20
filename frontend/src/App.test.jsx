import React from "react";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { webcrypto } from "node:crypto";
import App, { Auth } from "./App";
import PasswordLab from "./PasswordLab";
import { setCsrf } from "./api";
import {version as productVersion} from '../package.json';

// Prepare the real lazy module before timing integration interactions. Vite's
// cold transform competes with native-KDF workers and is not a UI interaction.
beforeAll(async()=>{await Promise.all([import('./ControlCenter'),import('./VaultCollection'),import('./Watches')]);},20000);

function mockWorkspace() {
  const user = {
    id: "user",
    email: "fixture@example.test",
    role: "owner",
    workspace: "workspace",
    csrf: "fixture-csrf",
    mfa_enabled: false,
    workspaces: [{ id: "workspace", name: "Fixture workspace", demo: 0 }],
  };
  const data = {
    assets: [],
    scans: [],
    findings: [],
    tasks: [],
    investigations: [],
    jobs: [],
    operations: [],
    members: [{ id: "user", email: "fixture@example.test", role: "owner" }],
    audit: { valid: true, events: [] },
    integrations: { groq_configured: false, scan_hosts: [], local_device_agent: true },
  };
  const fetcher = vi.fn(async (url, options) => {
    let value =
      url === "/api/status"
        ? { setup_required: false }
        : url === "/api/me"
          ? user
          : url === "/api/workspace"
            ? data
            : {};
    if (url === "/api/assets" && options?.method === "POST") {
      const asset = { ...JSON.parse(options.body), id: "asset" };
      data.assets.push(asset);
      value = asset;
    }
    return { ok: true, json: async () => value };
  });
  vi.stubGlobal("fetch", fetcher);
  return { data, fetcher };
}

describe("workspace flows", () => {
  it('refreshes findings after following a completed background watch alert',async()=>{
    const {data,fetcher}=mockWorkspace();
    const original=fetcher.getMockImplementation();
    fetcher.mockImplementation((url,options)=>{
      if(url==='/api/workspace'){
        const snapshot=structuredClone(data);
        return Promise.resolve({ok:true,json:async()=>snapshot});
      }
      if(url==='/api/watches')return Promise.resolve({ok:true,json:async()=>({watches:[],runs:[]})});
      if(url==='/api/notifications')return Promise.resolve({ok:true,json:async()=>({unread:1,notifications:[{id:'alert',kind:'advisory',watch_name:'Public package fixture',at:'2026-10-21T01:00:00Z',count:1,read:false,finding_ids:['new-finding']}]})});
      return original(url,options);
    });
    render(<App/>);
    await screen.findByText('Your security, handled.');
    fireEvent.click(screen.getByRole('button',{name:'Watches & alerts'}));
    const review=await screen.findByRole('button',{name:'Review findings'},{timeout:5000});
    // A background worker commits after the parent snapshot was loaded.
    data.findings.push({id:'new-finding',title:'Fresh watch advisory',asset_id:'asset',rule:'DEP001',severity:'unknown',confidence:'high',status:'open',kind:'dependencies',evidence:'New public provider observation',first_seen:'2026-10-21T01:00:00Z',last_seen:'2026-10-21T01:00:00Z'});
    fireEvent.click(review);
    expect(await screen.findByRole('button',{name:'Fresh watch advisory',exact:true})).toBeInTheDocument();
    expect(screen.getByRole('button',{name:'Findings 1'})).toBeInTheDocument();
  },15000);
  it('opens shared-vault review from a dashboard ownership request without collecting credentials',async()=>{
    const {data,fetcher}=mockWorkspace();
    data.ownership_requests=[{id:'fixture-proposal',vault_name:'Client handoff',expires_at:Math.floor(Date.now()/1000)+900}];
    const original=fetcher.getMockImplementation();
    fetcher.mockImplementation((url,options)=>{
      if(url==='/api/sharing/identity')return Promise.resolve({ok:true,json:async()=>({identity:null})});
      if(url==='/api/team-vaults' || url==='/api/vaults')return Promise.resolve({ok:true,json:async()=>({vaults:[]})});
      if(url==='/api/sharing/directory')return Promise.resolve({ok:true,json:async()=>({members:[]})});
      return original(url,options);
    });
    render(<App/>);
    fireEvent.click(await screen.findByRole('button',{name:'Review shared vault ownership'},{timeout:5000}));
    expect(await screen.findByRole('heading',{name:'Create your sharing identity'},{timeout:5000})).toBeInTheDocument();
    expect(fetcher.mock.calls.some(([url,options])=>url.endsWith('/ownership/accept') && options?.method==='POST')).toBe(false);
  },15000);
  it("shows real empty states instead of simulated security metrics", async () => {
    mockWorkspace();
    render(<App />);
    expect(
      await screen.findByText("Your security, handled."),
    ).toBeInTheDocument();
    expect(screen.getByText(productVersion,{selector:'b'})).toBeInTheDocument();
    expect(screen.getAllByText("00")).toHaveLength(4);
    // This panel is lazy-loaded; allow module startup under concurrent native-KDF tests.
    expect(await screen.findByRole('heading', {name:'What should we take care of?'},{timeout:5000})).toBeInTheDocument();
    expect(screen.queryByRole('button', {name:'Password lab'})).not.toBeInTheDocument();
    expect(screen.queryByRole('button', {name:/training workspace/i})).not.toBeInTheDocument();
    expect(screen.getByText("No findings in this view")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Agent desk AI" }));
    expect(
      await screen.findByText("Your agents are ready for evidence"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Run selected findings" }),
    ).toBeDisabled();
    expect(screen.getByText(/No AI output is simulated/)).toBeInTheDocument();
  });
  it("registers an authorized asset with CSRF protection", async () => {
    const { fetcher } = mockWorkspace();
    render(<App />);
    await screen.findByText("Your security, handled.");
    fireEvent.click(screen.getByRole("button", { name: "Add asset" }));
    fireEvent.change(screen.getByLabelText("Asset name"), {
      target: { value: "Fixture portal" },
    });
    fireEvent.change(screen.getByLabelText("Responsible team or person"), {
      target: { value: "Fixture team" },
    });
    fireEvent.click(
      screen.getByLabelText(
        "I operate this asset or have permission to assess it.",
      ),
    );
    fireEvent.click(screen.getByRole("button", { name: "Save and continue" }));
    await waitFor(() =>
      expect(fetcher.mock.calls.some(([url]) => url === "/api/assets")).toBe(
        true,
      ),
    );
    const [, options] = fetcher.mock.calls.find(
      ([url]) => url === "/api/assets",
    );
    expect(options.headers["X-CSRF-Token"]).toBe("fixture-csrf");
    expect(JSON.parse(options.body).authorized).toBe(true);
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });
  it("requires per-run permission before dispatching agent work", async () => {
    const { data, fetcher } = mockWorkspace();
    data.integrations.groq_configured = true;
    data.findings.push({ id: 'finding', asset_id: 'asset', title: 'Fixture password hashing', rule: 'PY001', severity: 'high', confidence: 'high', status: 'open', kind: 'python', label: 'auth.py', evidence: 'Redacted fixture evidence', first_seen: new Date().toISOString(), last_seen: new Date().toISOString() });
    render(<App />);
    await screen.findByText('Your security, handled.');
    fireEvent.click(screen.getByRole('button', { name: 'Findings 1' }));
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select Fixture password hashing' }));
    fireEvent.click(screen.getByRole('button', { name: 'Agent desk AI' }));
    const create = screen.getByLabelText('Create remediation tasks assigned to me; reuse existing active tasks.');
    expect(create).not.toBeChecked();
    expect(screen.getByLabelText('Create an investigation with the selected findings and draft brief.')).not.toBeChecked();
    fireEvent.click(create);
    fireEvent.click(screen.getByRole('button', { name: 'Run selected findings' }));
    await waitFor(() => expect(fetcher.mock.calls.some(([url]) => url === '/api/agents')).toBe(true));
    const [, options] = fetcher.mock.calls.find(([url]) => url === '/api/agents');
    expect(JSON.parse(options.body)).toEqual({ finding_ids: ['finding'], mode: 'triage', create_tasks: true, create_investigation: false });
    expect(options.headers['X-CSRF-Token']).toBe('fixture-csrf');
  });
  it("uses a separate MFA challenge before entering the app", async () => {
    const onDone = vi.fn();
    const fetcher = vi.fn(async () => ({
      ok: true,
      json: async () => ({ mfa_required: true, csrf: "challenge-token" }),
    }));
    vi.stubGlobal("fetch", fetcher);
    setCsrf("");
    render(<Auth setup={false} onDone={onDone} />);
    fireEvent.change(screen.getByLabelText("Email address"), {
      target: { value: "fixture@example.test" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "fixture-only-not-real" },
    });
    fireEvent.submit(
      screen.getByRole("button", { name: "Sign in" }).closest("form"),
    );
    expect(await screen.findByText("One more check")).toBeInTheDocument();
    expect(onDone).not.toHaveBeenCalled();
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
  });
});

describe("password lab privacy", () => {
  it("typing a password performs no network request or browser persistence", () => {
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    vi.stubGlobal("crypto", webcrypto);
    const storage = vi.spyOn(Storage.prototype, "setItem");
    render(<PasswordLab />);
    fireEvent.change(screen.getByLabelText("Password to evaluate"), {
      target: { value: "Password123!" },
    });
    expect(
      screen.getByRole("heading", { name: "Guessable" }),
    ).toBeInTheDocument();
    expect(fetcher).not.toHaveBeenCalled();
    expect(storage).not.toHaveBeenCalled();
    expect(screen.getByText("Not checked")).toBeInTheDocument();
  });
});
