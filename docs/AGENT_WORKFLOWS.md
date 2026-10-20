# SentinelOps workflow operators

## Local account review operator (0.9)

Unlock a personal or accepted shared vault and open its account review section.
The operator identifies exact origin-and-username duplicates and review dates
past the selected 90/180/365-day interval. Missing dates remain unknown and
future dates are flagged for clock review. The interval is a review reminder,
not a requirement to change a password periodically.

Select up to 20 entries or ask the operator to select candidates. Preview an
explicit mark-reviewed, archive or restore plan, review the names/accounts and
approve it. No mutation happens during selection or preview. Pending password
proposals block archiving so recovery is not hidden. Plans expire after two
minutes or when entries change; normal server revisions prevent overwrites.

Archived entries remain encrypted and can be restored in the Archived view.
Reloaded companion 0.9.0 excludes them from login filling, TOTP reveals and
password-preparation work. An old approval cannot access an archived login.
The latest eight recorded events are available under encrypted account history;
no prior password is retained there. Existing legacy history is not fabricated.
This deterministic workflow has no LLM input, provider calls or key requirement.

## Dependency watch operator (0.8)

In **Watches & alerts**, register 1–20 exact versions in requirements syntax or
package.json. Review the provider disclosure, cadence and task permission.
Schedules and task creation default off. Saving registers an application asset;
**Check now** queues the first check. Enabled schedules start at their next due
interval while the server runs. This fixed OSV operator needs no Groq key.

New package/advisory matches create in-app alerts and, only when authorized,
assigned remediation tasks. Repeated matches do not repeatedly alert. A partial
result retains previous observations, and coverage loss/restoration gets its own
alert. No result marks a task resolved or bypasses independent review.

Update the inventory when versions change. Editing or pausing cancels old result
publication; archiving retains historical evidence. An interrupted active check
requires explicit schedule resumption. A workspace owner can explicitly take
over another member's watch through editing/resumption. The alert bell opens
the central watch page; read acknowledgement is personal to each member.

The agent desk is a job interface, not a chat interface. A run owns an objective,
selected findings, explicit write permissions, evidence snapshots, execution
steps, and output records. This version uses **one AI planner** and four
deterministic tool workers. It does not claim multiple independent model reviews.

## Current execution

1. **Evidence collector:** selects up to 20 allowlisted rule records in the
   caller's workspace and snapshots scan versions. Raw code, email, asset labels,
   passwords, TOTP seeds, and private vault data are excluded from provider input.
2. **AI remediation planner:** requests one structured JSON plan from Groq.
   Missing configuration, provider failures, or malformed plans fail the run.
   There is no substitute or simulated AI response.
3. **Citation verifier:** requires each supplied finding exactly once. This
   validates references, not the factual correctness of generated instructions.
4. **Work dispatcher:** if authorized on the run form, creates remediation tasks
   assigned to the initiating contributor and/or an investigation brief. Active
   tasks are reused without reassignment or overwriting their existing guidance.
   Membership and evidence versions are rechecked before transactional writes.
   A failure rolls back all dispatched work. Calling the worker again after
   completion cannot create duplicates. An active run blocks another run in the
   same workspace.
5. **Progress checker:** records latest matching scan observations and task review
   state. The **Check progress** action refreshes this comparison without another
   model call. It does not perform a new scan or prove remediation from absence.

The user grants task and investigation creation separately, per run. Both are off
by default. Provider text is stored as advice, never executed as a command or
used as an API endpoint. Independent human review is still required to resolve
findings. Scan changes during planning require a new run before dispatch.

## Progress states

| State | Meaning |
| --- | --- |
| Awaiting recheck | No newer scan of the same asset, check kind, and label exists. |
| Still observed | A newer scan observed the same finding. |
| Not observed in recheck | A newer complete scan omitted it; this is not proof of a fix. |
| Inconclusive recheck | A newer partial scan omitted it. |
| Resolved by review | The existing independent-review workflow resolved it. |
| Unavailable | The original evidence cannot be compared. |

## Boundaries and next product increments

Runs use the local application's single worker and SQLite records. They are not
distributed agents or scheduled monitors. Restarted in-flight runs are marked
interrupted and never automatically replayed. Separate bounded operators now run
authorized device checks and account-change preparation. This release does not
autonomously submit external password changes, enroll external MFA, change OS
settings, or grant browser permissions. TOTP enrollment still requires the
service's enrollment flow.

Further operators should expose narrow, typed tools with explicit scope and
receipts: an authorized scan operator, a local device operator, an account
security enrollment guide, and an opt-in monitoring scheduler. Each needs
separate end-to-end verification before claiming those capabilities. Password
and TOTP cryptography must remain outside model access.

Tests exercise the planner with a synthetic provider transport; a live Groq run
requires a private `GROQ_API_KEY` in this application's `.env`.

## Private account-change operator

This operator is deterministic and runs inside the companion. No LLM sees its
approval plans, website/account selections, old passwords or staged passwords.

1. Unlock a personal or editable shared vault in the dashboard. Select up to 20
   logins and explicitly approve a 30-minute preparation plan. The plan contains
   exact HTTPS origins and entry IDs, encrypted under the vault's data key with
   action ID, vault ID, initiating user and personal/shared kind in its AAD.
   The server receives ciphertext, count, scope and expiry only.
2. In the companion, unlock the same vault and load approved work. The operator
   decrypts the plan, validates the current role/browser policy, expiry and
   selected entry origins, then explicitly claims a five-minute browser lease.
   Another browser cannot use that lease. An interrupted lease needs explicit
   resume; work is never replayed automatically.
3. Generate and stage a replacement locally. Persist it as ciphertext alongside
   the original login **before** opening a security page or filling any field.
   A closed popup, unsupported form or expired action cannot lose either value.
   The dashboard offers staged-password recovery, explicit promotion or discard.
   Vault copies strip pending-action state; the original remains untouched.
4. Open the exact origin's `/.well-known/change-password` URL through the extension
   worker. It is discovery, not verified site support. Redirects to a different
   origin cannot be filled under this approval. The user handles sign-in/MFA and
   can reopen the popup to continue. Only action ID and lease are kept in
   extension session storage; keys, passwords and plans remain local memory or
   encrypted vault data.
5. On explicit preparation, require one visible, unambiguous same-origin form
   with recognized new-password fields. Check account hints, form destination,
   lengths/pattern and confirmation fields before writing. Fill current password
   only into a recognized old/current field. Never submit, click a website
   button, bypass a challenge or broaden the approved origin. Unsupported/custom
   forms are reported honestly and retain the staged password for recovery.
6. Record `prepared` separately from `confirmed_by_user`. Only explicit user
   confirmation promotes the staged password to the saved login. A local
   encrypted receipt helps recover a lost outcome response. Discard requires the
   user to say the password was not used; the old login is retained. These are
   user reports, not independent website authentication tests.

The dashboard shows this private queue under Protect my accounts and within each
vault. It is separate from team findings/reports and AI triage. Newer vault
revisions require a fresh unlock rather than overwriting concurrent edits.
Cancellation, expiry, revocation and offboarding block subsequent broker calls.
They cannot undo form fields already filled or erase values a website received.
External site compatibility, real-browser lifecycle testing, per-site adapters
and independent success verification remain release gates.

## Windows host protection operator

Select a local/paired device and Host protection status. The server validates
authority and the operator-local target. Remote connections must opt in when
created, and the agent must also run with `--allow-posture`; protocol-v2 heartbeat
capability prevents silent execution on old or unconsented clients. Three fixed
read-only Windows scripts collect only five normalized protection states. Report
validation rejects raw fields and stale/inconsistent output before findings are
recorded. Optional AI triage receives only the existing allowlisted rule records.

The operator does not enable a firewall, change Defender, encrypt a disk, install
updates, elevate privileges or run arbitrary job/model commands. Unavailable tools
or denied access remain unassessed and make the scan partial. Other platforms are
explicitly unsupported in this release. The current Windows implementation is not
an endpoint detection product, patch manager or independent attestation service.
