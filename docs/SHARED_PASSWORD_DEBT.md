# Shared-password debt and rotation operator

Unreleased source, schema 14. This extends the existing encrypted credential
operator. There is no additional runner, agent executor or password collection
service. Browser testing and production rollout remain deferred.

## Debt means a shared login is still in use

Owners explicitly select shared-vault logins in the extension and consent to
sharing their entry titles and domains with the workspace. Only metadata enters
`credential_exposures`: client/vault references, a vault-bound SHA-256 reference
to the random entry ID, domain/nickname, platform, state, action/index references
and timestamps. The reference is not a password hash. There are no password, credential-username, authenticator-seed, unlock-key or
vault-payload fields. Only the selected entry title is copied as a nickname.

A client/vault/entry reference is idempotent. The same website or entry reference
in different vaults remains separate. Limits: 1,000 debt records per workspace;
1–20 selected items per operator approval. Mutations require the separately
approved owner/MFA workflow capability, live vault ownership and an explicit
client link. Vault, discovery and scanner tokens cannot call debt routes.

## One existing encrypted operator, status-only integration

1. Registration records `needed`; selecting a record does not rotate anything.
2. The extension maps opaque references back to local entry IDs after unlock and
   creates the existing encrypted account-action plan. No credentials enter the
   workflow capability. The same ordered items bind to debt records atomically.
3. The existing deterministic operator stages recoverable replacements locally,
   opens/prepares supported exact-origin forms and leaves final submit to the
   user. Its prepared/needs-attention reports set debt to `staged`.
4. Existing `confirmed_by_user` action outcomes set debt to `rotated` in the same
   SQLite transaction as the action outcome and audit. A crash rolls both back.
   This is user-reported website acceptance, not independent verification.
5. After testing the replacement login, an owner explicitly records `verified`.
   Neither rotation nor this confirmation reduces the shared-password counter.
6. To retire debt, the owner confirms delegated access works and the shared login
   is retired. The extension first archives the matching local entry through the
   existing encrypted vault write, checking its rotation receipt. Normal
   autofill excludes that archived entry; the encrypted recovery copy remains.
   Only then does the metadata request set `retired` and reduce the counter.

Retirement's backend API is an owner report; a zero-knowledge server cannot
independently certify plaintext client actions or external delegation. It does
not disable an external account or erase cached credentials. Guides point to
[official access flows](DELEGATED_ACCESS.md), never client password intake.

## Recovery, cancellation and reappearance

The extension persists a metadata-only pending binding after an encrypted action
is approved. If binding fails, Retry pending rotation link reuses that exact
existing action and does not approve a duplicate. An ambiguous action-creation
failure still requires inspecting Approved account actions before another plan;
there is no promise of exactly-once network effects.

If archival succeeds but metadata confirmation fails, the entry stays archived
and retirement can be retried idempotently. If local revision/receipt changed or
there is another pending password change, archival stops before the metadata
request. Repeated outcomes and retirement do not create duplicate audit events.

An owner can explicitly reopen retired debt when the shared login is reported
in use again. This clears the completed action binding, restores active debt
counts and preserves audit history. An archived local entry is not silently made
available for autofill; Restore archived login for rotation is a separate local
extension action after reopening.

Cancelled/expired operator plans do not erase local staged passwords or blindly
reset debt to all-clear. Existing staged proposals require review; the remaining
extension recovery UX for expired/orphaned proposals is still a follow-up item.
Restored backups cancel operator work while retaining historical debt metadata.

## Counter, map and reporting

The extension and Clients & Access show peak reported active records → current
active records per client. An empty registry is not evidence of no shared
accounts. Needed, staged, rotated and verified records all remain active debt;
only explicit retirement removes them from the count. Reopening raises it again.

The website is read-only for this normal workflow. Registration, approval,
verification, archive/retirement and reopening start in the extension. The API
reuses the existing progress/queue and includes action status in its metadata.
A full Client Proof Pack, independent external evidence and weekly reviews are
still unfinished.

## Automated evidence

The ten-record API regression runs needed → staged → rotated → owner-verified
through real existing queue/claim/outcome routes, then confirms that only
retirement lowers active debt. It also checks reopening, idempotence, atomic
cross-vault binding rejection, capability isolation, validation redaction,
transaction rollback and schema migration/backup preservation. Local helper
tests check metadata-only registration, pending-link retry without a second
approval, local archival before retirement and safe retry/restore. These are
isolated automated tests, not the deferred real-browser acceptance gate.

Final regression: backend 481 passed, one skipped; frontend 366 passed across
80 files. Web and content/popup/background builds passed in isolated validation
directories. No installed extension or Oracle deployment was replaced.
