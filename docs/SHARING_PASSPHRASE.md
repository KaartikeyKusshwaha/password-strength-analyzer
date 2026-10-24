# Change a sharing identity passphrase

Available in development build 0.10.0, under **Vault → Shared workspace vaults**.
Unlock your sharing identity, open **Change your sharing passphrase**, enter
the current passphrase, choose and confirm a new one, then approve the stated
connection/action consequences. Password values stay in the local crypto flow;
only a signed encrypted identity replacement is sent to the server.

This keeps your RSA encryption and ECDSA signing keys, public fingerprint,
existing grant wraps, vault key epochs, vault contents and teammates' access.
It re-encrypts the existing private-key bundle with a fresh Argon2id salt and
AES-GCM nonce. It does not generate replacement identity keys or rewrite vaults.

On commit the service revokes **your shared browser connections across all
workspaces**, cancels your unfinished shared credential-action leases, and
records a passphrase-change event in your current workspaces. Personal browser
connections and other users' connections/actions are preserved. The dashboard
locks; use the new passphrase and pair shared browser connections again.
Pending vault-ownership proposals you sent or received are also cancelled.
Any recoverable staged website password remains encrypted in its original
vault. Resolve it deliberately rather than assuming the website was unchanged.

Current protection is fetched before preparing the change. The client verifies
the private/public key match, and signs an authorization bound to your user,
fingerprint, previous encrypted-envelope hash and full new encrypted envelope.
The server validates the proof and rejects stale or conflicting replacements in
one transaction. Workspace viewers may maintain their own private identity;
this grants no additional shared-vault edit access.

Locking/hiding the UI or unmounting it while local work is pending invalidates
the operation before a mutation can be sent or published. A request already
accepted by the server cannot be undone by locking. If a response is lost or
arrives after locking, the next unlock fetches current server protection. A
network error does not prove that a change was rejected. Other idle dashboard
sessions check identity changes every eight seconds and lock when they differ.

## Limits

- This is passphrase maintenance, not forgotten-passphrase recovery. The current
  passphrase is needed. No recovery or silent identity replacement is available.
- Existing unlocked clients and decrypted keys cannot be erased. A compromised
  client can ignore UI locking. The same identity keys remain valid; this is not
  a remedy for private-key compromise.
- Old encrypted identities/backups remain unlockable with their old passphrase.
  Keep those passphrases for backups you retain. There is no external freshness
  or rollback authority.
- The server cannot decrypt the replacement or verify local strength checks.
  A malicious authorized client can still destroy its own encrypted identity.
- Automated native-crypto, API and UI lifecycle checks pass. Live browser
  acceptance and independent security review remain separate, unfinished gates.

Protocol details and limitations: [THREAT_MODEL.md](THREAT_MODEL.md).
