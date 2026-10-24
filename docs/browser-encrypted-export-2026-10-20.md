# Actual locked-vault encrypted export

On 2026-10-20, verified the selected dashboard vault was Browser acceptance and invoked Export encrypted backup while locked through its normal UI. Browser download-event observation timed out; that alone did not establish a download failure. The expected file was subsequently found in the user's standard Downloads directory, timestamped 20:37:02 local.

Artifact: `C:\Users\LENONO\Downloads\sentinelops-vault-6575b218598605553b5c4f07.json`.

Read-only verification of that exact file:

- 1,073 bytes, valid JSON, product SentinelOps encrypted vault.
- Version 2 envelope with Argon2id and the expected test-vault context.
- Envelope exactly matched the currently stored encrypted payload at revision 4 after archive/restore.
- The public practice password and website name were absent from the file's plaintext representation.
- SHA-256: `982e3f47308832d3d789663762eaab44e134ddedc870a19549191a918b84b73c`.

No master key, passphrase, sign-in credential, bearer token or decrypted entry was read from the file or printed. No import/replacement was performed. This proves export/download and current-payload consistency for one disposable vault; it does not establish a restore drill, offsite retention, backup freshness scheduling or recovery of a lost master passphrase.

## Restore attempt — blocked before submission

Selected Browser acceptance, unlocked with its established disposable passphrase,
and opened the normal encrypted-backup file chooser. The connector rejected
setFiles because its Edge extension does not have Allow access to file URLs
enabled. No alternate upload mechanism, direct API replacement, or other bypass
was used. An attempted read-only file-count query was unavailable in the DOM
scope and provided no evidence of file selection. Escape was sent, the vault was
locked again, and restore was never submitted. A read-only check confirmed the
test vault remained at revision 4.

Actual browser restore acceptance therefore remains unverified. It needs the
user to complete the file selection manually or explicitly enable the required
browser-connector upload permission. No such permission was changed or assumed.
