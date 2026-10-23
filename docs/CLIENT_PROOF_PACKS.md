# Client Proof Packs

Owners generate a private PDF/JSON snapshot from the extension and separately
approve a revocable, expiring report link. The website Workflows page retains
read-only history/downloads. Normal preview, generation, sharing and revocation
start and finish in the extension. No email, contact, external upload, scanner
execution or AI request is triggered by reporting.

## Content and scope

A snapshot contains the selected client's linked vaults, accepted/invited grants,
unretired external-account reports, associated staff's SentinelOps MFA enrollment,
offboarding runs and step outcomes/timestamps, scheduled removal rechecks,
shared-password debt and handoff receipts. Handoff evidence changed after sign-off
is flagged. Vault IDs distinguish identically named vaults. Reports do not equate
an invitation, login attempt or owner report with external-service access.

The owner can explicitly attach existing website/project check systems. This
client association is an owner assertion, not automatically inferred from a name
or hostname. Only status/time and current finding counts are exported; no raw
source, scan evidence, HTTP headers or package contents are included. Optional
posture is limited to paired devices belonging to this client's recorded staff.
It includes known fixed protection-check states, stale/missing coverage and
connection expiry. These are helper self-reports, not device attestation.
SentinelOps app MFA enrollment does not establish external account MFA.

A consistent preview transaction returns the exact source digest. Generation
rechecks source data in a write transaction and needs a fresh current owner
password and unused MFA/recovery factor. Invalid factors, changed source, invalid
associations or unrenderable reports commit no snapshot/factor consumption.
Reports are immutable: later client/access/device changes do not rewrite an old
report. Owners preview/generate a new snapshot for current evidence.

Branding is a bounded agency/report name. The PDF renderer uses packaged fonts
and no remote images, markup or active links. Unsupported glyphs are represented
as [U+XXXX], preserving identity rather than rendering blank squares; JSON retains
the original Unicode text. This is name branding, not a custom logo/theme editor.
The report is explicitly point-in-time evidence, not a security certification.

## Storage and integrity

Snapshot metadata is encrypted at rest using the service cipher. It is not a
zero-knowledge vault record: the service renders the selected personnel metadata.
Vault encryption, sharing keys and personal credential payloads are unchanged and
never enter these records. Staff identities/account labels are still confidential;
the extension previews them and states the recipient disclosure before sharing.

Canonical JSON is bound to a SHA-256 digest and authenticated by storage encryption.
The existing workspace audit-chain check/head and client-related event excerpt
are retained. Other-client event contents are omitted; the head is opaque. The
report creation audit records its snapshot digest. A database administrator can
rewrite an audit chain; neither the digest nor the chain is an independent
signature. A downloaded PDF and its JSON snapshot are ordinary unencrypted exports
and must be handled accordingly.

Collection fails rather than silently truncating oversized record categories,
step history or audit excerpts. Snapshots are bounded to 2 MiB; PDFs to 5 MiB and
100 pages. Per-workspace pilot retention limits are 500 snapshots and 1,000 link
records. The extension shows the newest 100 retained snapshots and up to 500 check
systems. These are pilot limits, not an unlimited retention promise.

## Sharing and revocation

A separate fresh password/MFA confirmation approves confidential sharing for
1-30 days (seven by default). This never grants vault, account or workspace access.
Only the random link token hash is stored; the secret is returned once. The URL
uses a fragment, so the token does not enter a server URL query. The public viewer
immediately removes that fragment and holds the capability in page memory, sends
it in an Authorization header to a cookie-free same-origin endpoint, and uses
text-only DOM rendering. It has no analytics, external resources or browser
storage. Reopening a cleared page needs the original complete shared link.

Anyone possessing that link can read/download its snapshot while authorized.
Every read checks token expiry, exact pack, revocation and the issuing account's
current owner/MFA authority. Expiry and revocation block new reads; downloaded
copies cannot be recalled. Revoking a snapshot revokes all its links and prevents
further sharing of that snapshot; generate a new report for new sharing consent.
MFA reset and workspace offboarding delete the issuer's link grants. Backup
restore deletes all proof-link grants but preserves encrypted report history.
A scoped reminder/security/vault connection cannot use report-owner endpoints.

## Release and acceptance

ReportLab/Pillow are pinned runtime dependencies. The release allowlist includes
the three public viewer assets; arbitrary backend/public files are not packaged.
Hosted rollout, native extension download/share acceptance and independent review
remain pending. Test snapshots contain synthetic staff and clients. PDF pages are
rendered and inspected outside a browser before release; this is layout QA, not a
live acceptance result or real agency validation.
