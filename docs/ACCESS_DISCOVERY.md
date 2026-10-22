# Opt-in account discovery and reported access

Unreleased source, schema 13. This is metadata collection and a manual access
registry, not external-account provisioning, identity verification or revocation.
No browser acceptance has been run during this implementation.

## What is stored

`access_grants` stores workspace/client/person references, a normalized hostname,
a user-chosen account nickname, reported role, source, state and timestamps.
There are no password, token, authenticator-seed, page-content, full-URL, query
parameter or vault-payload fields. Clients and people are checked in the current
workspace before owner-created manual records can be saved. Limit: 5,000 records
per workspace. Duplicate source/person/client/domain/label reports update the
existing record; repeated observations do not create duplicate audit entries.

Manual records use source `manual`, state `reported`. Login activity uses source
`extension_discovery`, state `observed`. The extension never claims successful
login; signup/password-change and cross-origin forms are excluded by the local
form classifier. Dynamic/unsupported forms may be missed. Retiring a record
sets `retired` and preserves history; later new reports reactivate it and add a
reappeared event. None of these metadata states proves actual platform access.

## Consent and capability

The existing proof-bound comparison-code handoff adds a separate `discovery`
scope, stored independently from vault, security and workflow connections. Its
30-day bearer is extension-origin bound, user/workspace bound, and cannot access
vault, scanner, offboarding or general workspace routes. Owners, analysts and
reviewers may report their own observations; viewers are read-only. Membership
and role are rechecked at each use and before mutation.

`GET /api/companion/discovery/context` exposes only the caller's consents and
clients they may currently select. Non-owners need accepted membership in a
shared vault explicitly linked to that client. Consent creation is checked
again against live access. A site has one chosen client/nickname per connection;
selecting another association requires a new explicit enable. Up to 100 chosen
sites per connection are supported.

The extension popup requests host permission for the exact active HTTPS origin.
The worker checks the current active tab, extension sender and permission before
persisting local opt-in. Only the trusted popup can enable, disable or disconnect.
A content-script message contains only `type: discovery-observe`; the worker
checks top frame, current tab/window and exact opted-in origin, then POSTs only
`consent_id`. The server derives all metadata from its stored consent and binds
the person to the authenticated caller. Extra observation fields are rejected.
No password or account-field values are read by the discovery classifier or message handler.

Unselected sites make no server request. Duplicate events are bounded to once
per tab/consent per minute in ephemeral worker memory. Removing host permission
clears local enabled sites; merely reopening the popup does not repopulate them
from server consent. Explicit enable is required again.

## Stop, revoke and recover

Disabling a site clears local collection first, even if the server is offline.
Disconnect clears the local connection and enabled sites. An unreachable grant
may remain valid until expiry, so Connections exposes user-owned discovery and
workflow grants for explicit service-side revocation. Existing reported records
remain visible until an owner retires them; deleting collection consent does not
pretend that an external account was removed.

Service-side disable/revoke, workspace offboarding and backup restore prevent
future observations. Restores preserve historical reported records but remove
all discovery capabilities and consents. Role loss or loss of the client's
accepted vault membership rejects subsequent observations. Schema 12 backups
remain supported and gain the empty metadata table during upgrade.

## APIs

- Owner app session: POST /api/clients/access-records and
  POST /api/clients/access-records/{id}/retire.
- Discovery bearer: context, consents, consents/{id}/disable, observe and revoke
  under /api/companion/discovery.
- Signed-in caller: GET /api/extension-capabilities and
  POST /api/extension-capabilities/{kind}/{id}/revoke for own workflow/discovery
  capabilities. These endpoints never return bearer tokens.

The owner access map merges these records with live vault membership evidence
without promoting observations into verified platform grants. No new external
SaaS credentials, OAuth scopes or paid resources were configured.

Automated evidence: full backend 476 passed with one skipped; final frontend suite
359 passed across 78 files. Tests exercise consent-only
requests, extra-field redaction, capability isolation, live role/client loss,
retirement/reappearance, migration rollback and restore revocation. Browser
acceptance remains intentionally deferred.
