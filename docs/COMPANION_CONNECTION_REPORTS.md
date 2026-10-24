# Browser connection control and reports — app 0.13.2 / companion 0.12.7

Browser & devices lists the signed-in user's active browser tokens with expiry,
last successful encrypted-vault contact and reported client version. Creating
a token alone has no contact record. The available version comes from the actual
downloadable ZIP manifest. Unavailable/malformed archive metadata stays unknown.

The extension sends its manifest version in X-Sentinel-Companion-Version during
pair verification and vault requests. The server records contact only after a
successful authorized vault read, then rechecks that the token is still active.
Matching reports are written at most once per minute; a version change is
recorded immediately. Missing/malformed versions remain unreported without
breaking older clients. No website URL/history, username, password, seed,
unlock key or ciphertext is copied into this report.

One report per token is stored under its owning account's private scope in the
existing entities table; no schema migration is needed. Public responses do not
contain bearer tokens or their authentication hashes. A scoped companion token
cannot list account connections. Revocation removes reports transactionally;
a late read cannot recreate them. Expired reports are pruned on another contact.
Restored metadata cannot reactivate revoked tokens; new tokens have new IDs.

The header is a client report, not attestation. A valid token can produce a
report. The UI does not infer installation, unlocked state, successful autofill
or continuous connectivity. It shows absolute contact times, distinguishes
different versions from absent reports and retains visible stale-data errors
after failed refreshes. It refreshes every 15 seconds while the tab is visible
and after local token creation/revocation.

## Disconnect one browser

Each active connection now has a reviewable Disconnect action. The signed-in
account can revoke only its own exact opaque connection ID, with the normal
session/CSRF protections. A bearer token cannot call this account endpoint;
another account receives the same not-found result as an unknown connection.
The ID is not the bearer token or its stored authentication hash.

Revoking one connection clears its contact report and interrupts only work leased
to that connection, in the same transaction as token deletion. Lease credentials
are cleared, while encrypted approvals and per-item progress remain intact.
Other tokens and work leased elsewhere stay active. An interrupted plan needs
an explicit resume and a fresh lease on another permitted connection. Pending
replacement passwords remain encrypted in their vault for reconciliation.

Personal/shared vault reads and writes, account-action reads, claims and results
recheck the current token and its scope inside the transaction that uses it.
This closes the gap where an earlier bearer lookup succeeded before revocation
but the later operation started afterward. A read already authorized before
revocation or plaintext cached on a device cannot be remotely retracted.

API: POST /api/companions/{opaque-id}/revoke. The normal UI first identifies the
exact named connection and explains the effect, with a Keep option. Failures do
not claim disconnection or hide the connection. Revoke all remains available.

The 0.13.2 focused checks passed: 40 backend cases and eight UI/operator cases.
They cover two-browser isolation, explicit resume, preserved staged progress,
transaction rollback after a forced deletion failure, account/CSRF isolation and
real personal/shared route interleavings that revoke after the initial bearer
lookup. Actual visual acceptance remains pending while browser control is disabled.

The full 0.13.2 run passed 327 backend tests (one existing TestClient warning)
and 194 frontend tests across 42 files; the app build passed. A fresh encrypted
backup preceded the local restart. SQLite integrity, schema 9, encryption key
and ten compared account/vault/sharing/connection/session/action/application
record groups matched. Application-entity comparisons exclude contact reports.
The served index matches the build and the new endpoint rejects unauthenticated
requests. The live owner's connections were preserved; revocation tests used
isolated fixtures. Ignored evidence: data/upgrade-0.13.2-baseline.json and
data/upgrade-0.13.2-result.json. The companion package remains 0.12.7.

## Reporting milestone verification on 21 October 2026 (0.13.1)

- Focused API/auth/privacy/revocation checks: 29 passed. Coverage includes bad
  tokens, cross-account isolation, bearer-only endpoint isolation, legacy and
  malformed versions, write coalescing, late-read revocation, CORS and bounded
  ZIP metadata. Focused frontend/companion checks: 18 passed.
- Full backend: 319 passed, one existing TestClient deprecation warning. Full
  frontend: 192 passed / 42 files. App and companion builds passed. The existing
  strength-bundle size warning remains. This is not an independent review.
- The 0.12.7 ZIP matches all 12 build files byte for byte; storage and activeTab
  permissions are unchanged, with no web-accessible private resources. SHA-256:
  ebf2be8a1420b01a351d703d4aa7d3ccd8bdafb5b1b873897609b7e5f0cd34b5
- An encrypted owner-data backup preceded a process-chain-verified restart.
  Schema remains 9. SQLite integrity and nine record-group comparisons passed:
  accounts, personal/shared vaults, identities/grants, connections/devices,
  sessions and application entities. The encryption key is unchanged. Served
  index matches the build; live preflight accepts the new header. Ignored
  records: data/upgrade-0.13.1-baseline.json and upgrade-0.13.1-result.json.
- The disposable passkey service on 8111 was stopped after confirming only its
  test account, zero active keys and zero pending challenges. Test data is
  retained. The main app remains on 8110.

Installed-extension reporting and visual panel acceptance remain pending.
Browser control reports local browser use disabled and no available apps or
browsers. No simulated owner-database report was submitted to manufacture an
installed-client result. Actual autofill remains a separate open gate.
