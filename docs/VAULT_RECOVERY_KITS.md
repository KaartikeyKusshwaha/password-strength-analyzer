# Offline personal-vault recovery kits — 0.16.0

This development feature requires preparation before losing a master passphrase.
It does not recover an account password, MFA, sharing identity or shared vault.
It does not introduce server escrow, trusted contacts, email resets, passkey vault
unlocking or emergency access. Independent crypto/client review remains a gate.

## User flow

1. Unlock a protected version-2 personal vault. Open Offline vault recovery and
   choose Prepare recovery kit. Enter the existing master locally.
2. The browser decrypts the latest revision, creates a fresh random data key,
   re-encrypts all entries under it, and prepares an encrypted JSON kit plus a
   separate random SRK1 recovery key. The live vault has not changed yet.
3. Download the kit and verify the file exists. Store its recovery key separately,
   then re-enter that key and acknowledge the effects. Activation submits only the
   new encrypted vault envelope, captured revision and a fixed rotation reason.
   A stale revision rejects activation without changing data or connections.
4. Activation locks the vault, revokes its personal browser connections and
   cancels all its unfinished personal account-action queues in one transaction.
   Other vaults/shared grants stay untouched. Existing staged proposed passwords
   remain encrypted in entries; external site changes are not undone.
5. If the master is lost, sign into the app and select that same vault. Choose
   Recover with a kit and supply the file, saved SRK1 key and new master locally.
   Current encrypted server data is the default source. Failed decryption never
   switches to older data. An explicitly selected kit snapshot requires an
   overwrite acknowledgement; later changes can be lost.
6. Recovery re-encrypts selected entries under another fresh data key and the new
   master, performs the same scoped revocations/cancellations, and locks. Prepare
   a new kit after recovery; prior kits cannot decrypt later data under this key.

Closing, hiding, idle locking, changing vaults or a parent lock discards pending
UI material and ignores late results. JavaScript cannot guarantee erasure of
immutable strings or browser/OS memory. If an HTTP write was already dispatched,
closing its UI cannot undo the transaction. Keep the file/key before activation;
if confirmation is lost, inspect the latest vault before manually retrying. No
automatic retries or alternate-source recovery are performed.

## Format and cryptography

The kit contains a format/version marker, exact vault context, random 96-bit kit
identifier, canonical UTC creation date, key_wrap and a version-2 encrypted vault
snapshot. A cryptographically random 256-bit SRK1 code directly supplies an
AES-256-GCM wrapping key; it is not a user password and is not password-derived.
The 32-byte data key is wrapped with a random 96-bit nonce. Associated data binds
format/version, vault ID, kit ID and creation date. The snapshot uses existing
context-bound AES-256-GCM data encryption and an Argon2id master-key wrap. The
browser locally verifies kit recovery before offering activation.

The recovery key is not embedded in the JSON file. The file contains neither
plaintext entries nor a raw data key. It is also an encrypted historical backup
that can be decrypted with the master used at kit creation; possession of that
master and the file is another route to the same historical data key. Keep the
kit private, even when its separate recovery key is stored elsewhere.

Parsing accepts only the supported structure and fixed KDF parameters, exact
24-hex contexts/identifiers, nonce/tag lengths, canonical creation dates and a
150 KB JSON bound. It does not execute imported code, fetch URLs or train a model.
Raw data/wrapping bytes are cleared in finally blocks and imported CryptoKeys
are nonextractable. The UI necessarily holds decrypted entries in JavaScript
while unlocked; this is not a hardened-memory guarantee.

## Key lifetime and limits

A master-passphrase change only rewraps the existing data key and does not disable
an exported kit. Use Invalidate older kits for future data to rotate the actual
data key while keeping the master unchanged. This provides no new kit. Creating
a replacement kit also rotates the data key. Already exported snapshots, old
application backups, compromised clients and previously revealed plaintext cannot
be erased or made secret again. Rotating protects subsequent current data under
a new key; it does not retract historical access. Restoring an older application
backup can reintroduce a prior data key and its recovery access. Rotate the data
key again before saving new secrets after such a restore; the server can revoke
connections but cannot rotate encrypted contents without client-held key material.

The service stores no recovery kit or SRK1 key. It cannot tell whether the user
kept a usable file, and the audit event is a client-reported activation intent,
not proof of possession or an independent recovery attestation. The server can
validate envelope structure, owner/context, revision and changed protection/data,
but cannot prove correct plaintext preservation or different hidden key bytes.
A compromised app session could already overwrite its owner's ciphertext; this
feature does not protect against such denial of service, XSS or a malicious
server/client. Account authentication/MFA remains necessary for service access.
There is no recovery if the master is lost without usable prior material.

No database migration or extension permission change is required. Schema 10 and
version-2 data envelopes remain in place. The ordinary revision-bound personal
vault write accepts a fixed rotation_reason. Browser bearer endpoints do not
accept that field or gain recovery authority. The same SQLite transaction saves
the new ciphertext, cancels scoped actions, clears leases, revokes scoped tokens
and records events. Backup recovery remains a separate operator workflow.

## Evidence

Tests cover a Python-generated Argon2id/AES-GCM interoperability vector, genuine
random kit creation, later writes, fresh-key rotation, explicit historical-source
selection, wrong keys, context/identifier/date tampering, malformed/oversized
files and bounded KDFs. UI cases cover local-only preparation, saved-key checks,
late crypto/HTTP results, hiding/cancellation and exclusion of secrets/kit bodies
from requests. API cases cover owner/context/revision enforcement, scoped token
and queued/leased-action cancellation, unrelated vault preservation, browser
intent refusal and rollback of a mid-transaction failure.

Native browser setup, download confirmation, recovery and key invalidation still
need user-operated credential confirmations. Automated tests do not establish
independent security audit approval or production readiness.

## References

- [OWASP cryptographic storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [RFC 5116 AEAD interface and AES-GCM](https://www.rfc-editor.org/rfc/rfc5116.html)

These inform standard cryptographic choices; they do not validate this product's
protocol, code, operational recovery procedures or security claims.


Development verification: the full Python suite passed 416 cases; six focused
recovery API cases also passed after adding the mid-transaction rollback case.
The complete React suite passed 225 cases across 49 files and its production
build passed. After final scope/historical-access wording, 12 focused UI cases
and another production build passed. The public native vector is reproducible
with `python tests/recovery_vector.py`, which checks without touching user data. A fresh encrypted backup preceded app startup; 15 checks preserved
schema 10, compared records, encryption key, owner setup, integrity and served
build. Edge was absent from connected browser inventory. The in-app browser
opened the actual updated sign-in screen, awaiting private owner sign-in. No
real vault recovery key was created or activated during this verification.
