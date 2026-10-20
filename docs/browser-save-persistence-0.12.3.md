# Secure save and persistence — companion 0.12.3

Actual Edge/user evidence, 2026-10-20:

1. User confirmed reload to 0.12.3. Private window screenshot showed the exact practice origin, username `practice`, and selected Browser acceptance vault.
2. Initial capture expired while instructions were being clarified. No success was claimed for that attempt. Opened a fresh capture from the same public demo form without submitting the website login.
3. User supplied the private window's `Encrypted and saved` confirmation screenshot.
4. Dashboard test: opened Vault & authenticator, explicitly selected Browser acceptance, unlocked with the established disposable test passphrase. The UI showed one saved login and its practice origin/username. No password reveal or copy action was used.
5. Explicitly locked the dashboard vault; decrypted account views disappeared. Unlocked again; the saved count remained one. Locked it again before resetting the public form for autofill testing.
6. The old dashboard tab initially could not load a lazy view following a rebuilt frontend. Its recovery button reloaded the workspace successfully. This stale-tab recovery is not evidence of a failed encrypted save.
7. Focused backend companion/multivault/shared-companion suite: 16 passed. Checks cover scoped bearer isolation, revocation, forbidden writes, cross-vault context rejection and exclusion of vault ciphertext from team evidence/report output. One Starlette TestClient dependency deprecation warning remains.

Local screenshot: `data/browser-acceptance-0.12.0/demo-login-synchronized-0.12.3.png`. User's success screenshot was supplied in chat. No valuable credentials, actual app sign-in password, bearer token, or passphrase was written to this evidence document.

Pending: actual selected-login fill from the installed extension, unrelated-origin denial, replacement confirmation and remaining multi/shared-vault browser cases. Browser control cannot operate the extension popup; the user was asked to select Fill this login on the now-empty practice form. No automatic submission or successful external login is claimed.
