# Browser connection reports — app 0.13.1 / companion 0.12.7

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

## Verification on 21 October 2026

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
