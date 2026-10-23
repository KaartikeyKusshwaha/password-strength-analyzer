# Weekly access review autopilot

The extension's access-workflow panel can enable, pause, compile, cancel and sign
off weekly reviews. No normal review action needs the website. An owner approves
metadata-only Groq planning with a current password and unused MFA/recovery code.
Consent lasts at most 90 days and covers current and newly linked client records
in the workspace. Scheduled compilation is weekly; explicit manual compilations
are throttled. Missing Groq configuration produces no substitute AI plan.

## Evidence and privacy

Deterministic collection covers linked vault invitations/memberships created in
the last seven days; active account reports without a current workspace member;
vault grants without a current workspace member; required sharing-key rotations;
account reports without an update in 30 days; and owner-reported shared-password
debt that is not retired. Account observations and manual reports are unverified
external access. Stale reports indicate missing recent evidence, not inactivity.
Vault usage is unknown; no dormant-vault-account claim is made.

Source snapshots bind client/member IDs, roles, grant acceptance/creation,
rotation epochs/state, report state/timestamps and debt state. They never read
vault payloads, key envelopes, passwords, TOTP secrets or account entry contents.
Groq sees only opaque evidence IDs and fixed issue categories, severity,
confidence and predefined guidance; client names, domains, account labels,
person identifiers and individual source rows are excluded from its request.

Every source collection is bounded to 10,000 rows per category and rejects an
over-limit source instead of silently reviewing an incomplete source. Up to 20
prioritized items are planned per batch, with full candidate, already-reviewed
and omitted counts. After sign-off, compiling the next batch skips items covered
by an unexpired sign-off against the same source digest. Changed source metadata
requires a fresh review. Previously covered issues can resurface after their
seven-day review validity expires. Omissions are not signed off as complete.

## Existing execution engine

The existing WatchService scheduler calls a bounded, fair 25-workspace scan. It
creates one current-week review and an existing `jobs` record atomically, advances
the next due time, then dispatches through `reviews.Runner` and its existing
executor/deduplication. The existing agents collector, Groq request, strict
citation-coverage schema, dispatcher and progress checker are reused. No second
runner, external commands, additional scanner rules or vault protocol changes
were added. Empty evidence needs no provider call and can receive an explicit
empty sign-off; it does not certify security or external account removal.

Live owner/MFA, consent and source digest checks occur before provider planning
and again before accepting results. Cancellation and pause prevent late results
from dispatching work. Restarted in-flight jobs become interrupted through the
existing startup behavior and are not automatically replayed against Groq; the
owner can explicitly compile again. Scheduled execution does not catch up every
missed week. Unfinished reviews block another current batch until signed off,
cancelled, failed or expired. Provider/network/schema failures are explicit.

## Sign-off and follow-up

The popup shows up to five proposed actions first, with remaining guidance and
source facts under details. Sign-off binds the exact evidence and accepted plan
digest, requires a fresh current password and unused MFA/recovery code, and
rechecks source metadata inside the task transaction. It creates or reuses open
follow-up tasks through the existing dispatcher. Repeated weekly evidence reuses
an existing open task for that source key. The progress checker includes those
reused task references but never infers that an account was fixed.

No sign-off grants or revokes access, changes a password, enables external MFA,
or marks a finding resolved. Actual removals use the separate scoped offboarding
approval and local sharing-key rotation. Generic scanner-agent creation rejects
access-review findings so it cannot bypass this owner sign-off flow.

Backup restore pauses policy consent, cancels unfinished reviews and invalidates
bearer grants. A newly approved read-only reminder connection includes review
availability in its toolbar alert count; older expiry-only grants retain their
original scope until reconnected. Reminder reads still cannot sign off or act.

## Release and acceptance

This is unreleased source. Hosted rollout and the consolidated native browser
acceptance remain pending. That session must cover enable/compile/sign-off,
changed source rejection, next-batch omissions, cancellation during planning,
restart recovery, read-only reminders and actual follow-up task links. Mocked
provider tests establish transport/redaction/schema and execution behavior;
they are not live Groq availability, real-agency validation or a security audit.
