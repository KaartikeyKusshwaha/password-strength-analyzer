# One extension and service — app 0.18.0 / companion 0.13.0

The current user-selected scope has three tools. Assign-3 email/phishing
detection was explicitly removed; new email scans, operations and review steps
are rejected before work is queued. Existing evidence is preserved.

| Original project | Connected workflow |
| --- | --- |
| password-strength-analyzer | Local in-page strength checks and generation, explicit encrypted saving, multi-vault management, exact-origin autofill, local reuse review and optional hash-prefix breach checks. |
| assign-4 | App sign-in with optional TOTP, local setup QR generation, replay controls, recovery codes, and encrypted authenticator entries for compatible external services. |
| vulnerability-scanner | Scoped local/paired-device TCP observations, authorized website headers, Python/dependency checks, recorded findings and agent planning. Header banners and open ports do not prove CVEs. |

The extension's three shortcuts open fixed tool destinations on its connected
SentinelOps origin. No token, master password, page URL or website credentials
are placed in those links. No extension permissions were added. Reload the
existing unpacked extension once to load its updated popup.

The default home page shows these three tools and **Approve and run agents**.
Advanced individual checks are collapsed. Choose an available device and approve
one scope: 16 fixed TCP ports plus separately available host protection and cached
Windows Update observations. Operators run the checks in sequence, save findings,
and optionally use Groq for one planning call. The dispatcher links existing
active tasks and creates missing follow-up work. Recurring execution is not
implicitly enabled, and the hosting server is not substituted for a user device.

Vault unlocks, provider sign-in/challenges and final credential changes remain
explicit user actions. There is no universal provider MFA-enrollment or password
change API. Agents never receive vault plaintext or authenticator keys and cannot
approve remediation, install software or change device settings.

Actual Edge acceptance completed the automatic three-check workflow, produced
two listener observations, and completed AI planning with one new task and one
existing task linked. Fourteen ports timed out and BitLocker access was denied;
coverage correctly stayed partial. Cached update status was observed, with cache
freshness still unverified. This is evidence of workflow execution, not proof of
device safety or fixes. See `unified-browser-acceptance-2026-10-21.json`.

The frontend dependency watch was also refreshed through Edge using the current
0.18.0 package-lock.json. The prior 205-version snapshot did not include the new
QR dependencies. The replacement inventory contains 233 exact versions, all
233 were assessed by OSV, with no unsupported/excluded records and no advisory
matches returned. Scheduling and automatic task creation remain off. This is a
snapshot check; future source changes require reimport, and no matches does not
establish application safety.
