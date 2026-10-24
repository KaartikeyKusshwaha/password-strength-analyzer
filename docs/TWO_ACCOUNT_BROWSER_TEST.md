# Two-account browser sharing test

Run `npm --prefix frontend run build:companion`, then
`npm --prefix frontend run test:acceptance` with Python application
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
The current test prepares and approves one real two-vault workflow through the
built extension UI and waits for the existing server worker; it does not patch
the runner or fake its completion. A third disposable persistent Chromium profile loads the actual
built MV3 companion. Real API-created, single-vault member connections are
installed only in that profile; no host permissions or manifests are altered.
The popup unlocks both vaults with fingerprint verification, saves encrypted
logins, adds a disposable authenticator and reopens to generate its code. The
code is checked against an independently calculated HMAC-SHA1 TOTP.

The owner workflow connection uses the actual extension-origin comparison-code
protocol with authenticated account approval. Separate exact-vault owner tokens
remain necessary. The test unlocks each affected owner vault, waits for the
extension's automatic rotation completion and never clicks a rotation button.
It counts exactly one workflow approval and two rotation writes. It then selects
Proof Pack in the extension, previews the real snapshot, approves generation
with a fresh recovery factor and downloads the generated PDF.

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
local two-account security gate; cloud/profile acceptance,
recovery, helper installation and independent security review remain
separate. Source is served by Vite to allow the cache-adversary probe to import
the same client crypto; release bundles are verified by the other CI jobs.

Only public disposable fixture credentials are used. External browser requests
are blocked. No browser profile, trace, secret or database is uploaded as a CI
artifact; ephemeral runner storage is discarded with the job.

After offboarding, both previously working bearer tokens return 401 and the real
popup's unlock action switches to Reconnect your vault rather than exposing
entries. Extension local storage is checked for passphrases, saved passwords
and the authenticator seed; database/journal checks include those values too.
This does not claim that a removed person loses copies of older data.

## Verified result

CI run [40101677179](https://github.com/KaartikeyKusshwaha/password-strength-analyzer/actions/runs/40101677179),
commit 948cfd9: **1 passed in 33.0 seconds**, including storage plaintext checks
and direct AES-GCM rejection with the correct new authenticated context.
The same run passed six built-extension cases, 77 PostgreSQL/backup tests
(one skip), 42 helper/release tests, 55 agency/crypto tests and container startup.
The first attempts exposed test selector/acceptance-form timing issues; they
were corrected without changing the production app or weakening security.

Expanded real-service companion coverage passed in
[CI 40102342586](https://github.com/KaartikeyKusshwaha/password-strength-analyzer/actions/runs/40102342586),
commit c1105ee: **1 passed in 33.0 seconds**. All four jobs passed, including
the extension, PostgreSQL/agency and container layers. This adds real encrypted
popup saving, reopen/TOTP and revoked-token/UI checks to the earlier scenario.
No runtime application changes were necessary.

The extension-led version passed in
[CI 40103269347](https://github.com/KaartikeyKusshwaha/password-strength-analyzer/actions/runs/40103269347),
commit 7055acb: **1 passed in 19.4 seconds**. Preparation and approval use the
real popup, both rotations continue automatically after the exact owner vault
unlocks, and the test observes exactly one approval POST and two rotation POSTs.
The extension previews/generates the real private client Proof Pack, downloads
it and verifies its PDF header and nonempty size. The previous saving, TOTP,
revocation, cached-key rejection and storage confidentiality assertions remain.
