# SentinelOps

An access control tower for agencies: know who can touch each client, remove access in one approved run, and report the outcome to the client. This is the product direction; the client access map and durable offboarding workflow are not yet shipped. Existing encrypted vaults and extension workflows form the foundation.

**Hosted app 0.22.0 / [companion 0.23.0 prerelease](https://github.com/KaartikeyKusshwaha/password-strength-analyzer/releases/tag/companion-v0.23.0).** The last verified Oracle companion download is 0.22.1; its update is pending SSH reachability. Use disposable credentials until the security and acceptance gates in [the agency master plan](docs/AGENCY_MASTER_PLAN.md) pass. See [actual release and browser evidence](docs/EXTENSION_ACCEPTANCE.md); implementation is not a claim of production readiness.

## Extension-first access workflows

Normal save/fill/authenticator and supported assessment actions run in the
extension. The website manages vaults, results, connections and settings.
Client access mapping, approved offboarding, rotation queues and client proof
packs are the next planned workflows. Existing scanner and investigation engines
are supporting capabilities; they are not the product's primary proposition.
Agents do not receive passwords, vault keys or authenticator secrets. CSV import
from existing password managers remains the adoption path.

Email/phishing detection was removed from the current product at the user's
request. New email scan, operation and combined-review submissions are rejected.
Existing historical evidence is preserved.

## Connected workflows

- **Combined security reviews:** preview and approve up to six scoped checks in one run, collect their findings and optionally create AI-guided remediation tasks. Individual coverage and cancellation remain visible. Execution does not prove remediation. See [review scope and evidence](docs/SECURITY_REVIEWS.md).

- **Control center:** give a target to an operator. It registers the asset, runs the scoped check, records findings, and can dispatch AI-guided remediation tasks when explicitly authorized.
- **Browser assistant:** recognized signup and password-change forms receive a local strength dialog, generation, and private encrypted saving. Exact-origin login filling requires a selected entry and never submits a form.
- **Multiple vaults:** separate passphrases and encrypted contents, purpose/color, lock timers, default selection, archive, browser access/save/fill rules and exact-origin scopes. The same website can exist in several vaults. Copying unlocks and re-encrypts the destination locally.
- **Account passkeys (development):** reauthenticated enrollment/removal, browser WebAuthn sign-in and preserved app MFA. Native Edge enrollment, sign-in, expiry and service-side removal passed in a separate disposable localhost app; remaining lifecycle checks are pending. Requires a supported configured HTTPS domain or localhost; the current 127.0.0.1 origin is explicitly unavailable. This does not unlock vaults or enroll other websites. See [passkey scope and evidence](docs/PASSKEYS.md).
- **Browser connections:** see token expiry, last successful encrypted-vault contact and reported companion version, compared with the downloadable package. Disconnect one connection while preserving the others; its leased account work is interrupted and requires explicit resume elsewhere. Reports do not certify installation or working autofill. See [the connection contract](docs/COMPANION_CONNECTION_REPORTS.md).
- **Shared workspace vaults (preview):** separate encrypted sharing identities, individually wrapped vault keys, signed invitations, trusted-channel fingerprint checks and owner/admin/editor/viewer roles. Revocation requires a new encryption key for remaining members. Accepted shared vaults can connect to the companion for selected login fills, code reveals and encrypted saving according to current roles and browser policy.
- **Vault ownership handoff:** an expiring signed proposal and explicit successor acceptance rotate the vault key, preserve approved member access, and revoke this vault’s existing browser connections. Addressed requests appear on the dashboard. See [the handoff protocol and limits](docs/OWNERSHIP_TRANSFER.md).
- **Sharing passphrase maintenance:** re-encrypt your existing private sharing keys locally without replacing your fingerprint or vault grants. A signed, revision-bound change revokes your shared browser connections and cancels unfinished shared account actions across workspaces. Cached keys and older backups cannot be erased; this is not identity-key rotation or recovery.
- **Workspace offboarding:** owner password/MFA revokes workspace sessions, device connections and shared grants, cancels active jobs and requires affected vault key rotation. Personal vaults stay with the account. Vault owners must complete a two-party handoff before offboarding. Workspace ownership and erasing cached copies are separate limitations.
- **Vault cryptography:** new vaults use Argon2id (64 MiB, three passes) to wrap a random AES-256-GCM data key. Master changes re-wrap that key; legacy PBKDF2 vaults remain readable and have an explicit upgrade path. Optional offline recovery kits must be prepared before the master is lost; shared-identity recovery remains unimplemented.
- **Account adoption:** local login-CSV import from Chrome, Bitwarden, 1Password and LastPass, encrypted backups, local weak/reused-password checks, opt-in HIBP hash-prefix lookups, and encrypted TOTP.
- **Account review operator:** find exact website/username duplicates and accounts due for a user review. Preview and approve up to 20 entries to mark reviewed, archive or restore. Archived entries retain encrypted credentials but are excluded from the updated companion and password-change plans. Latest eight account events stay inside the encrypted payload; unknown history stays unknown. No passwords are changed based on age alone.
- **Vault activity:** page through recorded saves, access changes and account-action lifecycle events for one authorized vault. Private account observations appear locally after unlock. The service log contains no credential fields; earlier unrecorded activity and local fills/reveals are unavailable. See [the timeline's coverage](docs/VAULT_ACTIVITY.md).
- **Approved account work:** select up to 20 logins in an unlocked vault and approve an encrypted preparation plan. The companion stages recoverable replacements, opens exact-origin security pages and prepares recognized change forms. It never submits them. Old logins remain until you explicitly confirm the website accepted a change. The private queue appears in the control center; unsupported forms remain visible as needing attention.
- **Device operator:** assess one authorized private IP and up to 64 TCP ports. Run locally or pair a remote device that polls scoped jobs and returns results. TCP checks use network connects only. Open ports are observations, not proven vulnerabilities.
- **Host protection checks:** on Windows, query the selected operator computer's firewall profile configuration, Defender antivirus/realtime state and system-drive BitLocker protection status using fixed read-only status commands. No arbitrary commands, elevation, recovery-key access or settings changes. Other platforms, missing providers and denied permissions remain unsupported/unassessed.
- **Other checks:** Python AST patterns, exact pinned dependencies via OSV and HTTPS headers on allowlisted domains. Submitted code is processed in memory and excluded from provider input.
- **Advisory severity:** manual checks and watches calculate CVSS base scores from OSV vectors, retaining the advisory, version and reported source. Missing/ambiguous ratings stay unknown; coverage and rating evidence appear with findings. This does not prove local exploitability. See [severity scope](docs/ADVISORY_SEVERITY.md).
- **Dependency watch operator:** register exact PyPI/npm versions in Watches & alerts. Explicitly approve scheduled OSV checks (6 hours to 7 days), new-match alerts and optional assigned remediation tasks. Update versions, pause or archive a watch; stale and interrupted results cannot publish. Alerts have per-member read states. The server must remain running; partial/provider failures stay visible. This deterministic operator requires no LLM key.
- **Agent workflow:** one Groq planner plus deterministic evidence, reference, dispatch and progress workers. Model output cannot execute commands or approve remediation. An independent reviewer resolves findings.

Vault secrets are excluded from workspace reports and AI requests. Metadata such as vault names, policies and website scopes is visible to the server. Current limitations and adversaries are documented in [the threat model](docs/THREAT_MODEL.md).

## Run locally on Windows

Requires Python 3.12+, Node.js 22+, and a Chromium browser for the unpacked companion. No Docker is needed.

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
cd frontend
npm ci
npm run build
npm run build:companion
cd ..
.venv\Scripts\python.exe companion/package_extension.py
.venv\Scripts\python.exe run.py
```

Open http://127.0.0.1:8110/. On first launch, obtain the bootstrap token locally from `data/.bootstrap-token` and create the owner account in the app. Never send passwords, master passphrases, connection files or tokens to chat. The owner bootstrap is deleted after setup.

Create the vault yourself and choose its master passphrase locally. The app sign-in password and a vault’s master passphrase are separate. An app password reset cannot unlock an encrypted vault.

SQLite remains the **local development** store. [Encrypted operator backups and isolated restore tooling](docs/BACKUP_RECOVERY.md) are available. Postgres migration, production deployment/backup operations, independent client/sharing audit, mobile clients, native passkey acceptance and extension-store publication are unfinished production gates. Shared vaults are a development preview with explicit limitations in the threat model.

For a persistent Python/SQLite pilot, [Oracle VM deployment files](deploy/oracle/README.md) provide a no-Docker systemd/HTTPS setup and a release bundle that excludes local data and secrets. Actual VM deployment and public browser acceptance still require verification.

## Browser companion

Build/package as above. In Edge or Chrome’s extension-management page, enable developer mode and load **`companion/extension/dist`**, the folder containing `manifest.json`. Do not load the nested `assets` folder. After rebuilding, reload the installed extension.

The packager validates permitted files, writes a deterministic ZIP and prints SHA-256 checksums. See [release verification and its limits](docs/EXTENSION_RELEASES.md). Packaging does not confirm installation or browser acceptance.

In **Browser & devices**, select the intended vault and create its scoped connection using your app sign-in password and MFA if enabled. Pair it in the extension. Multiple vault connections can be remembered; switching locks the previous vault.

Choose a personal or shared connection. A shared token can retrieve only its
selected accepted vault plus your encrypted sharing identity. It cannot read
other vaults or workspace APIs. Unlock locally with the sharing passphrase and,
for another owner's vault, verify their fingerprint through a trusted channel.
Read-only members can fill selected logins but cannot save. Owners/admins can
restrict shared browser saving/filling, exact login origins and lock timeout.
Turning off browser access revokes all existing tokens for that shared vault.

The toolbar popup and dedicated secure-save window share the same session/cryptography module. They
check current policy before saves, fills and code reveals. A revision or key
epoch change requires another unlock; pending unlocks cannot revive a locked
session. There is no automatic form submission or universal password-change API.

On a supported HTTPS signup form, focus the new-password field. The assistant suggests a password, fills the matching confirmation field, and opens a separate extension-owned window when you choose Save securely. Choose the intended vault, unlock, and confirm saving before the three-minute request deadline. The private page is not exposed as a web-accessible resource or embedded in the website. Custom forms still need explicit compatibility testing. A closed shadow root alone is not a defense against a malicious page.

Vault changes sync as encrypted envelopes. Captures are held in worker memory for up to three minutes. Closing the extension’s vault UI drops local key references. Browser disable/archive revokes the selected vault’s tokens; close already-unlocked windows to clear their local contents.

## Connect a device to a hosted dashboard

In **Browser & devices**, create a device connection, specify the permitted private IPs, and download its private JSON file and Python agent. Keep the JSON private; it contains an expiring bearer credential. On that device:

```powershell
python sentinelops_device_agent.py --consent --connect sentinelops-device-connection.json
```

Keep the process running; stop it with Ctrl+C. Select that connection in the control center to run a check. The client independently enforces its configured IPs, port limits and verified HTTPS destination, and refuses redirects. There is no automatic startup installer yet. Revoke the connection in the dashboard to stop future jobs.

For host posture checks, explicitly enable that permission when creating a new
connection and run device agent 0.7+ with an additional `--allow-posture` flag.
Existing ports-only tokens do not acquire the permission during upgrade. The
agent heartbeat declares whether the local flag is enabled; an old or locally
unconsented client fails the posture job rather than reporting a clean device.
Use `python sentinelops_device_agent.py --version` to check the downloaded client.
In the control center choose **Check a device → Host protection status**.
The scope is the selected agent computer, not a remote LAN machine or cloud host.

Reported Windows firewall profiles may be inactive. A passive Defender mode may
coexist with another antivirus, which is not assessed. BitLocker protection is
queried through `Win32_EncryptableVolume.GetProtectionStatus`; only the resulting
state is kept. This is not a complete disk-encryption, patch, software or compromise
assessment. Raw PowerShell output is discarded; no system changes are attempted.

## Optional integrations

`GROQ_API_KEY` and `GROQ_MODEL` belong in the local private `.env`. Without a key, deterministic checks work and AI execution is unavailable; there are no simulated model results. Provider calls contain only allowlisted rule records, not raw code, emails or vault secrets.

OSV exact-pin vulnerability lookups and HIBP padded hash-prefix password lookups require no API key. HIBP checks are opt-in and on demand while a vault is unlocked. A no-match result is not a claim that an account is safe. Email breach monitoring is a different service and is not implemented.

Set exact authorized public hostnames in `SCAN_HOSTS` before website checks. Public deployments require HTTPS in `APP_ORIGIN`. A hosted server cannot stand in for a user’s computer; pair the device instead.

## Verification

```powershell
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m pytest -q --basetemp data/test-run-fresh
cd frontend
npm test
npm run build
npm run build:companion
```

Choose a fresh pytest directory when rerunning on Windows. Tests use synthetic credentials and mocked providers, except an explicit test that opens and observes its own local TCP listener. They do not certify live Groq execution, universal account rotation, browser-store compatibility or independent crypto review.

The legacy command-line learning tool remains in `password_analyzer.py`. It is not the product’s password-management interface.


**Windows Update checks:** separately opt-in to offline-cache counts and update-related restart status with device agent 0.8.0. Results connect to reviews and AI task planning; no updates are installed or reboot performed. Cached zero does not prove patch coverage. See [scope and setup](docs/WINDOWS_UPDATES.md).

**Offline vault recovery:** prepare an encrypted kit and a separate random key before forgetting a personal-vault master. Activation/recovery rotates the data key and revokes only that vault’s browser connections and private action queues. Current and historical sources are explicit; no server escrow or automatic snapshot substitution. [Protocol and limits](docs/VAULT_RECOVERY_KITS.md).
