# Agency Phase 0 evidence

22 October 2026. The access-control-tower pivot is accepted; it is not yet a
shipped access-map or autonomous connector offboarding service.

## Companion 0.23.0

- Includes recognized username/email-focus invitations already committed in
  source, with existing exact-origin, role and vault policy checks preserved.
- In-page login/TOTP notices now give a direct toolbar instruction, with Dismiss
  as their only button. Removed the content-to-worker toolbar-launch command;
  no `chrome.action.openPopup` is called by this flow. Private secure-save windows
  remain extension-owned and are not removed.
- Production content, popup and worker built successfully; packager validated
  the manifest and allowed-file set. ZIP SHA-256:
  `013ee78c9fa3b428d94f982c326eb5a752591d73bb42b6d2462ecc5cf42f3cac`.
- All 336 frontend tests passed across 73 files. Count decreased from 338 because
  popup-launch diagnostics tests were replaced by retired-route/inline-notice
  behavior tests; this is not a claim of reduced functionality elsewhere.
- Actual bundled worker fixture passed monitoring, opt-out, bound private-save,
  no-plaintext-storage and ignored retired-popup-command checks.
- Installed Edge acceptance of 0.23.0 still requires reload and actual use.

## Sharing gate

`tests/test_shared_offboarding_crypto.py` combines real RSA-OAEP/SHA-256,
ECDSA/P-256, Argon2id-protected identity material and AES-GCM payloads with two
registered isolated accounts and actual authorization routes. It is an
independent native protocol implementation, not new production crypto.

It establishes initial recipient decryption; API access after acceptance;
revocation of the removed member's browser token and vault read; writes blocked
until rotation; next-epoch payloads readable with the new key; failure using the
cached old key even when old epoch AAD is tried; no fixture password or raw data
key in the SQLite dump; and valid audit chain. Cached old payload remains readable
to the former member. Rotation does not remotely erase previously known secrets.

The new test plus existing shared-vault and companion suites passed 16 tests.
An initial attempt hit an inaccessible OS temporary directory before app setup;
rerun used a fresh ignored workspace-local pytest directory. No production
database, identity or permission was modified by this test.

The complete current backend suite passed **448 tests, one skipped**, with one
Starlette TestClient deprecation warning, in 159.89 seconds. The report is kept
under ignored data/phase0-full-backend-results.xml. Counts are current collected
suite results, not an assertion that the native browser gate passed.

**The required two-account browser removal/rotation gate is still pending.**
Automated tests do not substitute for it. The cloud secure-save, TOTP, multiple
shared-vault browser workflows and recovery acceptance also remain pending.

## Reuse and validation gates

Do not build a parallel worker system: operation dispatch, cancellation,
agent-job/task state and existing watcher scheduling must be mapped into the
durable workflow state model first. LLM planning must not authorize mutations.

No agency interviews or design partners have been recruited. The minimum three
pain reports and connector shortlist are unmet. Google OAuth requirements were
checked against official sources in the master plan; no OAuth app or partner
authorization has been created. No connector phase or real-data pilot is approved
by merely shipping this extension release.

## Release transport status

The local 0.23.0 unpacked build and deterministic ZIP are ready. The Oracle SCP
connection timed out before uploading the release; no server replacement was
performed. Public HTTPS /api/status still returned 200 with setup complete.
The prior deployed companion 0.22.1 remains the last verified cloud download
until an authenticated download/manifest check proves a newer deployment.
Local reloads and a downloadable GitHub release artifact must not be described
as a successful Oracle deployment. SSH reachability needs resolution.

## Publication evidence

- Branch `codex/credential-security-lab` was pushed to the user's repository.
- [Draft PR #1](https://github.com/KaartikeyKusshwaha/password-strength-analyzer/pull/1)
  is open against main. It covers the accumulated platform foundation and states
  the incomplete agency product and browser gates. It has not been merged.
- [Companion 0.23.0 prerelease](https://github.com/KaartikeyKusshwaha/password-strength-analyzer/releases/tag/companion-v0.23.0)
  contains sentinelops-companion.zip. A fresh public download's SHA-256 matched
  `013ee78c9fa3b428d94f982c326eb5a752591d73bb42b6d2462ecc5cf42f3cac`.
- GitHub's asset metadata reports the same digest and uploaded state. Publication
  proves artifact availability, not installation or acceptance in Edge.
- A limited pattern review of 760 reachable new blobs found no checked Groq,
  GitHub token, private-key or AWS-ID patterns and no sensitive tracked paths.
  The final follow-up documentation changes contain no credential material.
- The user has no agency-owner contacts yet. The interview kit in
  AGENCY_VALIDATION.md is ready; no outreach, partner or pain-report evidence exists.
