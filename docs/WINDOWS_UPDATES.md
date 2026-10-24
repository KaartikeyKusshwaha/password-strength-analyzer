# Windows Update observations — app 0.15.0 / device agent 0.8.0

This is an opt-in assessment of the selected operator computer's Windows Update
offline cache and update-related restart requirement. It is not a full patch
inventory, a live catalog refresh, installed-software discovery or an automated
patching service. It complements TCP and host protection checks in the central
operations feed, check history, combined reviews and optional AI/task workflow.

## Permission and protocol

Hosted installations require a paired device. Creating the connection requires
current account authentication and separately selecting update-status access.
Existing posture/port connections are not upgraded to this permission. The local
client also needs `--consent --allow-updates`, and its private connection file
must contain `allow_updates: true`. Agent 0.8.0 uses protocol 3; older clients
can still serve their previous scopes but cannot run update jobs. Unsupported
or locally unconsented clients fail the queued update job explicitly.

Update jobs target only 127.0.0.1 or ::1 on the selected agent computer and have
no TCP ports. LAN addresses, foreign result types, unsolicited host reports,
expired/reused leases and revoked connections are refused. One typed report
contains only platform, timestamp, fixed source marker, cached counts and the
reboot boolean with per-observation state/reason. No titles, KB numbers, machine
IDs, registry dumps, paths or full provider output are retained or sent to AI.

## Fixed local tools

`Microsoft.Update.Session` creates a searcher with `Online = false`. It searches
only cached, uninstalled, unhidden Software updates. ResultCode must be 2
(succeeded); partial/provider failure is unassessed. Total counts are bounded to
10,000; the security counter includes the Security Updates and Critical Updates
classification GUIDs. These are update classifications, not vulnerability CVSS
ratings. No CWE mapping or particular exploitable CVE is established.

`Microsoft.Update.SystemInfo.RebootRequired` reports whether a restart is needed
to complete an update installation/removal. It is not a general reboot detector.
Both fixed PowerShell tools use an absolute Windows executable, no profile,
stdin, shell expansion, user-interpolated commands or elevation. Each has a
35-second timeout and bounded accepted output. The normal posture collector's
allowlist is separate, so granting posture never starts update commands.

Cache freshness is unknown. Zero cached updates does not establish that the
computer is fully patched. Drivers, hidden updates, installed-patch coverage,
third-party software, product support lifecycle and compromise are not assessed.
No online refresh, installation, download, EULA acceptance, reboot, service or
security-setting change is requested. COM provider/internal Windows behavior is
outside SentinelOps's attestation boundary. Users review Windows Update on the
actual computer and coordinate changes with its owner.

## Persistence and recovery

Schema 10 adds default-denied `allow_updates` and `updates_enabled` device
columns transactionally. Missing/incompatible columns under an applied marker
and unexpected unmarked partial layouts fail closed. Legacy tokens, posture
consent, vault ciphertext and account records are preserved by migration.
Backups accept schemas 8, 9 and 10, validating the matching layout. Restore
migrates only a new destination and revokes device/browser grants and sessions.
The main app is backed up and protected-record comparisons are required before
upgrade. The server cannot independently attest a paired device's self-report.

## Verification

Tests cover count/type bounds, platform/timestamp restrictions, output redaction,
fixed offline commands, timeouts/denial, local execution, paired double consent,
protocol 1/2 refusal, exact report/lease matching, unrelated payload rejection,
schema migration defaults/idempotence, coverage UI and approved agent dispatch.
A live local Windows probe on 21 October reported zero cached pending updates
and no update-related restart. This was a cache observation, not patch assurance.
Ignored evidence: `data/windows-update-live-20261021.json`.

## Primary references

- [WUA Online property](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-get_online)
- [WUA search criteria](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search)
- [Update-related reboot status](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-isysteminformation-get_rebootrequired)
- [WSUS classification GUIDs](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ff357803(v=vs.85))


Final evidence: 411 Python tests, 215 full React tests plus 17 final focused UI
checks, and production build passed. A fresh actual-store backup/restore drill
passed 11 checks; main-store upgrade passed 16 checks and preserved records and
encryption key. Actual Edge ran the local operation and displayed the typed
cache/reboot observations, explicit scope limits and zero findings. Its approved
AI option did not create a job without findings. The audit chain remained valid.
Screenshot and structured result: `data/browser-acceptance-0.15.0/`. Real paired
update-device installation/acceptance and full/live patch coverage remain open.
