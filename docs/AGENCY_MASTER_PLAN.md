# SentinelOps: agency access control tower

Accepted direction, 22 October 2026. This plan supersedes scanner-first and
password-manager-first positioning in older documents. It describes required
work, not completed product capabilities.

Know who can touch each client, remove access in one approved run, and produce
an honest report of removals, retained access and unresolved work. Vaults support
that outcome. Normal actions start and finish in the extension; the website is
the control room for Clients & Access, Workflows, vault administration and Settings.

## Preserve and reuse

- Preserve Argon2id/AES browser encryption and the existing sharing protocol;
  bug fixes only before independent review. Server receives no vault keys or
  credential plaintext. Connector credentials require separate protected storage.
- Reuse scoped expiring tokens, revocation, CSRF/origin checks, rate limits,
  workspace isolation, audit chain, exports, progress and cancellation.
- Extend the existing operation/agent pipeline into the durable workflow runner;
  do not introduce a competing dispatcher. The LLM proposes metadata-only plans;
  deterministic steps execute stored approved scope.
- Reuse credential staging as a rotation queue. Website submit remains with the
  user; a manual mark-done is a user report, not independently verified rotation.
- Preserve personal/multiple/shared vaults, roles, invitation/ownership workflows,
  MFA/passkeys for app sign-in, import/export/recovery and deployment/backups.
- Make MFA mandatory for workspace owners and administrative access through a
  staged enrollment gate; do not lock current owners out without enrollment.
- Keep CSV import prominent. Move low-priority password health/recovery/export
  controls under Settings without deleting their underlying capabilities.

## Phase 0: shipping and proof

- Publish the current branch and a reviewable PR. Ship companion 0.23.0 with
  username-focus invitations and no in-page toolbar-popup launcher.
- Finish installed cloud secure-save, TOTP, multi-vault and recovery acceptance.
- Blocking test: two separately signed-in accounts share a vault; remove one,
  rotate its data key, confirm the removed member's old token is rejected and
  cached old key cannot decrypt newly encrypted payloads. Old cached plaintext
  and historical payloads cannot be erased remotely.
- Automated crypto/API tests strengthen evidence; they do not substitute for
  the two-account browser test or independent review.
- Interview 5–10 agency owners, recruit 2–3 design partners, ask for a concrete
  departing-person system inventory. Record evidence before connector priority.
- Exit: browser blocking test passes, at least three agencies report the pain,
  and a connector shortlist exists. No interviews or validation are claimed yet.

## Phase 1: map and durable execution

People, clients, access_grants, credential_exposures, connectors, workflows,
workflow_steps and handoff_records need scoped migrations and clear provenance.
Manual/connector/extension observations must never be labelled verified grants.
Map vault memberships to clients through explicit binding, not a guessed vault
name. Implement a workspace-scoped read API and Clients & Access page. Convert
assets into systems under clients and the control center into Workflows.

Inspect and reuse `backend/agents.py`, `backend/app.py` operation/progress paths,
`backend/reviews.py` if present, `backend/store.py` transactions/audit,
`backend/sharing.py`, `backend/ownership.py`, credential-action and watch logic.
Durable steps require leases, idempotency keys, retries and reconciliation after
an uncertain external response. Never claim exactly-once external effects solely
from a local transaction. Recheck membership/approval at execution time; enforce
last-owner protection, dry-run and validated LLM plans. Exit: a crash-resume test
does not repeat an already completed effect; the map displays vault grants.

## Phases 2–3: offboarding and shared-password debt

- Vault connector: discover, revoke member, rotate sharing key in unlocked client,
  two-party owner handoff, freeze connections. Never move crypto to the server.
- Popup: metadata plan, one approval, live progress, cancel, verify, report.
- Demo 1: remove a test member from two shared vaults; report each outcome with
  no credential secrets in workflow records.
- Per-site opt-in discovery: domain and account label only, explicit client
  association. No passwords, paths, queries, page text or covert browsing history.
- Credential exposures/debt: track shared logins, official delegated-access
  alternatives, retirement and rotation. Accept official grants; no intake forms.
- Rotation queue: needed → staged → rotated → verified, retaining honest
  user-reported/unverified statuses. Prompt for local unlock when needed.
- Exit: ten disposable credentials traverse the supported queue with evidence.

## Phases 4–5: connectors, time limits and client proof

Google Workspace first; the next connector follows design-partner evidence,
with GitHub a candidate rather than assumed demand. Manual connector for the
rest, explicitly unverified where no API confirms removal. Google suspension,
GitHub membership removal and scheduled last-day observations prepare a plan;
admin approval precedes revocation. Rechecks at +24h/+7d/+30d alert on reappearance.
Demo 2 covers vaults/Google/GitHub with mock servers before actual accounts.

Time-boxed access includes day-27 reminder for a 30-day grant, expiry revocation
under stored narrow approval, recheck and failure alerts. Add Client Proof Pack
PDF/link, weekly proposed access review, person_handoff/client_offboard with
sign-off. Bind existing site/project checks to client evidence, not new panels.
Client reports distinguish assertions, connector observations and verification.
Validate demand for questionnaires/proof packs and pricing, not assume it.

## Phase 6: device and production gates

Verify Windows helper installation/pairing; then macOS. Use posture snapshots,
retrieve-device and wipe checklist attestations. Device-gated vaults are later,
not a reason to redesign encryption now. Independent review covers crypto,
sharing, runner and connectors before valuable credentials. Store release,
signed helpers and recurring off-server backups remain required.

## Hide, remove, park

- Gate old checks, investigations, run logs, watches, combined-review UI, raw
  evidence and port-scan UI under `/advanced` using `ADVANCED_UI`. Keep engines
  and tests; remove duplicate panels only after replacements pass.
- Remove phishing routes/UI/rules and back up then archive historical mail
  records. No destructive historical-data purge without the exact archived
  scope, retention/recovery plan and required approval.
- Remove routine website redirects and in-page buttons calling `openPopup`.
- Park passkey vault unlock, arbitrary-site automatic MFA/password changes,
  SMS/push MFA, additional scan rules and universal/custom-frame compatibility.
- Compatibility acceptance names Google, Meta, LinkedIn, TikTok, Shopify,
  WordPress, GitHub and Slack; this list is a target, not current certification.
- Stop expansion if the removal guarantee cannot be made sound; do not build
  connector phase before three agency pain reports. Reassess positioning if
  partners will not run real offboarding after connector validation.

## Google OAuth constraints checked now

Official Directory guidance distinguishes read-only user access from broad user
management and separate security/group permissions. Discover with the narrowest
scope; request write scopes only for concrete approved operations.
[Directory scopes](https://developers.google.com/workspace/admin/directory/v1/guides/authorizing).

External testing uses named test users (normally capped at 100); public sensitive
or restricted access needs applicable verification. Internal-only configuration
is restricted to its Workspace organization, not all design partners. Workspace
admins can block apps even after verification. Refresh-token/test-mode limits
must be handled as connector-expired alerts, not hidden retries.
[Google OAuth app states](https://developers.google.com/identity/protocols/oauth2/production-readiness/overview).

No OAuth app, production scope grant, partner interview or external security
audit has been created by this document.
