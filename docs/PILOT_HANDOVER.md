# SentinelOps pilot handover — 24 October 2026

Live app: https://sentinelops-pilot.onrender.com/
Hosted application code: 66f1931. App 0.25.0, companion 0.26.0.
Render deployment: dep-dbeak3jrjlhs73f2didg, verified Live in 54.7 seconds.
The installed Edge companion was reloaded and visually verified at 0.26.0.
Later commits add tests and documentation, without changing the deployed runtime.

## Product delivered

The extension opens with client access and one task at a time: offboarding,
client handoff, access review, time-boxed freelancer access, Proof Pack or shared
password debt. The website holds client/vault administration, history,
connections and settings. Scanner and password-manager controls are secondary.

| Capability | Implemented behavior | Practical boundary |
| --- | --- | --- |
| Client Access Map | Live linked-vault membership, manual reports, opted-in domain/account labels | External reports are labelled; no SaaS connector verification |
| Approved offboarding | Immutable scope, fresh password/MFA approval, durable removals, crash recovery, token revocation, progress and report | Removes selected SentinelOps vault access; cannot erase cached old data or terminate external website sessions |
| Vault key rotation | Local encryption and remaining-member key distribution; continues automatically for the matching unlocked vault | Each locked vault must be unlocked; errors stop for explicit retry |
| Freelancer access | Signed scoped invitation batches, approved expiry, reminders and rechecks | Scheduler needs the backend awake; Render Free is not a punctual worker |
| Handoffs | Ownership proposal/acceptance, independent receiving-owner sign-off, evidence freshness | External grants/device return still require evidence or attestation |
| Weekly access reviews | Consented metadata-only planning, proposed actions and sign-off | AI does not receive credentials or authorize removals |
| Client Proof Packs | Scoped PDF/JSON, separately approved expiring/revocable links | App evidence is not an independent compliance certification |
| Shared-password debt | Registry, staged supported changes, retirement/trend tracking | Website final submission and acceptance confirmation remain explicit |
| Account tools | Encrypted personal/shared multi-vaults, exact-origin fill, secure save, TOTP, CSV import, recovery/export | Valuable credentials await independent review and remaining live acceptance |
| Device/project checks | Existing deterministic scanner/helper engines and posture evidence | Helper GUI pairing/distribution acceptance remains incomplete; helpers unsigned |

## Verification

- Local release verification: 428 frontend tests, 54 backend agency tests and
  root `npm run build` passed for 66f1931.
- CI run 40099884284 at fbb5c59 includes six real built-extension Chromium
  cases. The agency case prepares and approves a two-vault plan, observes live
  status polling and opens the report against an isolated routed mock service.
  It sends approval once and never uses the operator's browser/profile/accounts.
- The backend CI layer separately covers 55 agency/crypto cases, including
  removed-member cached-key rejection against a new encrypted payload. This is
  protocol verification, not two-account installed-browser acceptance.
- CI 40101677179 at 948cfd9 adds a real local FastAPI/Vite/Chromium scenario:
  two registered accounts, two UI-created shared vaults, signed invitations,
  one approved removal workflow, both key rotations, retained-owner access,
  cached old-key rejection and actual database plaintext checks. It passed
  in 33.0 seconds; all other CI jobs passed. This local full-stack test uses
  no mock API and no operator profile. Hosted/installed acceptance stays open.
- Expanded CI 40102342586 at c1105ee also loads the real built MV3 companion:
  encrypted shared-vault saving, reopen/TOTP checked against independent HMAC,
  both bearer revocations and the popup's refused-unlock/reconnect state pass.
  No test secrets appeared in extension storage or database/journal files.
  The full scenario passed in 33.0 seconds; every CI job passed. This covers
  the local companion/service integration without certifying hosted Edge use.
- Prior cloud browser evidence proves owner/MFA setup, vault unlock and
  user-confirmed exact-origin autofill. The live client map loads without error;
  the current pilot workspace has no configured clients.
- Encrypted off-server backups and isolated restore checks passed, including
  the first scheduled Neon pull. Keys and backup data are excluded from Git.

## Unfinished release gates

1. Live cloud secure-save/TOTP, two-account shared-vault removal/rotation,
   recovery and handoff/Proof Pack acceptance in installed browsers.
2. Agency interviews/design partners. The master plan explicitly gates Google
   Workspace/GitHub connectors on three real agency pain reports. They have not
   been implemented; do not sell arbitrary-platform offboarding.
3. Independent security review, extension-store release, signed helper packages
   and native Windows/macOS install/pairing acceptance.
4. Reliable always-awake scheduling. The free-only hosting constraint remains;
   sleeping Render Free cannot guarantee exact-time unattended expiry.

The pilot is delivered with these limits. The full master plan is not complete.
Detailed evidence: EXTENSION_ACCEPTANCE.md, EXTENSION_E2E.md,
FINAL_BROWSER_CHECK.md and RENDER_NEON_PILOT.md. No passwords, tokens, MFA seeds
or encryption keys belong in this handover.
