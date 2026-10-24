# Read-only background access reminders

An owner can separately approve a **reminders** connection using the comparison
code flow. It lasts up to 90 days and sees only expiry-policy client names,
expiration times and execution states. It cannot read vault contents, approve
plans, grant or remove access, scan systems or pair devices. The existing access
operator connection remains eight hours; it is not extended for notifications.

The server projects policies whose reminders have been recorded, blocked policies,
queued execution, unlock waits and scheduled departures ready for approval.
Completed, cancelled and unapproved policies are omitted. Metadata is scoped to
the approved workspace and current owner/MFA authority is checked on every read.
Extension origin, token expiry, revocation and current role remain enforced.
Backup restore and MFA disable revoke reminder grants. Each owner can revoke all
of their reminder connections for the workspace from Settings, or disconnect
one from the extension. Forgetting a local connection does not revoke a server
bearer if the server is unreachable; the UI states this limitation.

The extension worker re-establishes its 15-minute alarm when it starts and when
the reminder connection changes. It checks the already-approved service host
permission before cookie-free, no-redirect requests with the token in the
Authorization header. An **R** toolbar badge means expiry items to review; **?**
means unavailable checks or required reconnection. Revoked/expired/role-lost
connections stop repeated polling. Normal offline errors keep the alarm so the
next check can recover. Active secure-save captures keep their own badge until
they finish, after which the reminder badge is restored. Site-specific badges
can take precedence on particular tabs; the reminder popup remains available.

Only a count, local connection identifier, last-check time, server-grant expiry
and check state are cached in extension storage. Client names and individual
alerts are fetched on explicit popup refresh, not written into that cache.
The worker checks connection identity after responses so a disconnected or
replaced connection cannot publish late results for the new connection.
Opening the reminder panel does not automatically perform account actions.
An owner reconnects the separate operator capability to approve or execute work.

This is periodic polling, not real-time push, email or an OS notification.
Browser closure/sleep, alarm delays, missing permission and server downtime delay
notification delivery. An alert is not evidence that access is fully removed:
waiting-unlock states still need local key rotation. Scheduled expiry effects
continue on the server independently of whether the browser is open.

Native browser/worker acceptance and matching hosted deployment remain pending.
Source tests exercise independent scopes, ninety-day expiry, cross-origin and
live-owner/MFA failures, revocation, restore, comparison-code cancellation,
worker permission checks, cookie/token transport, stale responses and capture
badge priority. No notification permission, paid service or new credential store
was added.

New reminder approvals also include weekly-review availability, without its plan
or evidence. Older expiry-only grants do not gain that scope; reconnect with the
new comparison-code consent to include reviews. See WEEKLY_ACCESS_REVIEWS.md.
