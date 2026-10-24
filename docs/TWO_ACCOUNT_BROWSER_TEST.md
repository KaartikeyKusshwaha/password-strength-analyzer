# Two-account browser sharing test

Run `npm --prefix frontend run test:acceptance` with Python application
dependencies installed and Playwright Chromium available. CI runs this as the
`sharing-browser` job. This is independent of the operator's Edge profile.

The test starts the actual FastAPI app and Vite client on loopback ports 18221
and 18222. It refuses an existing test directory/server, explicitly disables
cloud database/provider settings and uses a fresh temporary SQLite installation.
Production administrator MFA stays enabled. No fixture API route is added.

Account registration and MFA enrollment use the real HTTP endpoints. Two
separate Chromium contexts hold the resulting sessions. Sharing identities,
two shared vaults, encrypted entries, signed invitations, fingerprint checks,
invitation acceptance and key rotation use the actual client UI and cryptography.
The test prepares and approves one real two-vault workflow through the API and
waits for the existing server worker; it does not patch the runner or fake its
completion.

A separate member page uses the real sharing module with disposable test
passphrases to retain the old handles before removal. After rotation it attempts
to decrypt the new payload, an epoch-altered copy, and the new ciphertext
directly using the old AES key with the correct new authenticated context. All
three must fail, while
the remaining owner must reopen and read both vaults. The report's audit chain
must validate and exclude fixture secrets. The actual installation's database
and journal/WAL files are also checked for the known fixture passphrases and
entry passwords; this is stronger than checking only API/report text.

These are registered accounts against a real local service. They are not hosted
Render/Neon accounts or an installed Edge extension test. This strengthens the
local two-account security gate; cloud/profile acceptance, revocation of browser
bearers, recovery, helper installation and independent security review remain
separate. Source is served by Vite to allow the cache-adversary probe to import
the same client crypto; release bundles are verified by the other CI jobs.

Only public disposable fixture credentials are used. External browser requests
are blocked. No browser profile, trace, secret or database is uploaded as a CI
artifact; ephemeral runner storage is discarded with the job.

## Verified result

CI run [40101677179](https://github.com/KaartikeyKusshwaha/password-strength-analyzer/actions/runs/40101677179),
commit 948cfd9: **1 passed in 33.0 seconds**, including storage plaintext checks
and direct AES-GCM rejection with the correct new authenticated context.
The same run passed six built-extension cases, 77 PostgreSQL/backup tests
(one skip), 42 helper/release tests, 55 agency/crypto tests and container startup.
The first attempts exposed test selector/acceptance-form timing issues; they
were corrected without changing the production app or weakening security.
