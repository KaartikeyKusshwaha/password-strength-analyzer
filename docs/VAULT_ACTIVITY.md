# Vault activity timeline

Development build 0.11.0 adds **Show vault activity** inside personal and accepted
shared vaults. It combines a durable, paginated service log with the private
account observations already retained in each encrypted vault. It does not
invent historical activity or turn a saved credential into proof of a website
password change.

## Service records

The authenticated `GET /api/vault-activity/{personal|shared}/{vault_id}` endpoint
returns up to 50 events by default, at most 100 per request. `before` is an
exclusive sequence cursor, so events arriving now do not shift older pages.
Refresh starts again at the newest recorded event. All returned events can be
paged; there is no fixed "latest eight" limit on this service log.

Personal activity requires ownership of that exact vault. It includes new
private-scope records and older workspace metadata records only where the actor
is the owner and the target is that exact personal vault. It remains available
when the owner switches workspaces. It does not expose another person's vault
even to a workspace owner. Future personal events are stored under a private
`personal:<user-id>` audit scope, outside workspace reports.

Shared activity requires current workspace membership and an accepted grant to
that exact shared vault. Pending invitations and revoked/offboarded users cannot
read it. Workspace switching or query parameters cannot expand the scope. The
service checks this on every page; previously displayed or copied records cannot
be erased. Current workspace actor names are displayed; unavailable/former
actors are labelled without looking up email addresses outside the workspace.
There is no new companion-token authorization to read the timeline.

Recorded events cover metadata creation/properties/default changes, archive and
restore, encrypted initialization/saving, observed protection-envelope changes,
browser connection creation/revocation, shared invitations/removal/key rotation,
and application-backup recovery. Private account plans are associated through
their stored vault ID: approval, claim/resume, lease interruption, expiry,
cancellation and browser-reported outcomes. Expiry/interruption is recorded once
when processed by the service, not asserted to have run exactly at the deadline.
The timeline query never selects vault ciphertext, action manifests, token
values, credential fields or account titles. Mutations and their new events
commit in the same transaction; failed writes do not generate success events.

An encrypted save says only that a revision was persisted. A protection change
is inferred from the submitted encryption envelope. Account preparation/outcomes
remain browser or user reports. Fills, copies, local reveals and local unlocks
are not sent as telemetry, and have no service-log entry. Old unscoped browser
events and previously unrecorded saves cannot be attributed or reconstructed.
Generic unrelated workspace events are not included. Timeline IDs/timestamps,
actor IDs and action types are service-visible metadata, not encrypted secrets.

The existing hash-linked audit history is not an independent signing authority.
This endpoint returns a filtered view, not a full-chain integrity proof. A
database administrator can rewrite history. Retention, external checkpoints,
rollback protection and production-scale query/index design remain deployment
work. The development SQLite backup limit is still 128 MiB.

## Encrypted account observations

After unlocking, the same panel displays the latest eight supported local events
per current entry, including archived entries. It sorts reported device times,
shows 50 at a time and permits loading the rest locally. Titles and dates are
decrypted in the browser and never included in activity requests. Accounts with
missing/unsupported history are labelled as having no supported recorded history.
Removing an entry or trimming its older history removes those local observations;
they are not reconstructed from the service log. Device clocks may be incorrect.

Locking removes these private observations immediately. Closing the panel or
switching vaults discards pending responses; scope/generation checks prevent an
old response from appearing under a different vault. Failed/revoked reads clear
stale service records and show the error, rather than an invented empty history.
These are application safeguards, not secure erasure of a compromised browser's
memory or previously copied data.

## Recovery coverage

The backup tool now validates **all** existing audit scopes, including personal
ones, before creation/restoration. Recovery retains historical records, adds
per-vault recovery events, and records cancellation of unfinished account work.
It does not make activity before the snapshot current again. See
[BACKUP_RECOVERY.md](BACKUP_RECOVERY.md) for account/membership rollback limits.

Live browser acceptance and independent security review remain separate gates.
