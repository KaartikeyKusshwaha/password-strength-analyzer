# Combined security reviews — app 0.14.0

Security reviews coordinate one approved scope across 1–6 existing assessment
operators. The React screen previews each selected check before submission.
Supported steps are scoped TCP ports, fixed Windows posture, allowlisted HTTPS
headers, Python patterns, exact PyPI/npm pins and email text indicators.
Accounts and vault changes remain separate encrypted approvals. The assign-3
trained classifier and inbox ingestion are not added by this coordinator.

`POST /api/security-reviews` binds approval to the currently selected workspace,
name, check list and optional AI task-dispatch permission. A switched workspace
rejects an old draft, and the component remounts on workspace switches. Existing
contributor, target allowlist, device scope and posture consent checks apply.
Raw submissions total at most 120 KB; the ordinary request-body limit also
applies. Raw source/email is held only in worker arguments, not serialized in
review/operation history. Individual steps cannot independently request AI.

The workspace is reserved against another review, operation or manual AI job.
Checks run sequentially and retain individual complete, partial, failed,
cancelled or unassessed results. A paired device has a two-minute response
window for each step. Timeout cancels its child operation; an already running
device may finish its local check, but a late service result is rejected.

After assessments, one optional Groq job plans remediation for at most 20
collected finding IDs. It uses existing evidence/citation validation, per-run
task permission and progress tracking. Overflow, failed steps or failed AI
planning keep the review partial. The review exposes assessment and triage
status separately. No findings produces a no_findings triage state rather
than a fabricated model plan. Completed execution is not proof of a repair.

Cancellation stops pending work, active child leases and unfinished linked AI
work. Completed observations/tasks remain. Fresh membership checks precede
steps and final publication. Offboarding, startup recovery and encrypted-backup
restore stop active reviews. No replay/resume is attempted because raw input is
not stored; a new approval and submission are required. The parent/child/job
links and state changes appear in the normal workspace records and report.

## Evidence and remaining acceptance

- Backend review cases cover mixed-module execution, one AI job, raw-input
  exclusion, permission removal, workspace binding, cancelled approval, retained
  completed observations, real paired leases/late-result refusal and restart.
  Backup restoration includes interrupted review/check states.
- React cases cover scope preview, one approved request, raw draft clearing,
  retained rejected drafts, partial coverage and reservation/viewer controls.
- A live Groq API test in an isolated synthetic store completed two checks,
  three findings, one planner run and three tasks with a valid audit chain.
  It did not place test data in the owner workspace.
- This is a coordinator for existing checks and approved planning. It does not
  supply automatic device repair, universal password changes, trained phishing
  classification, scheduling for all review types or independent risk correlation.
- Actual Edge acceptance passed through the existing owner app using normal
  sign-in. A real authorized localhost TCP/Windows posture review recorded
  port 8110 open, three firewall profiles and Defender enabled, and BitLocker
  unassessed because permission was denied. The parent remained partial.
  The live Groq run included its one finding and created one open task.
  The updated review screen visibly showed per-check coverage and linked to
  the completed agent workflow. This single case does not certify every type.
- Automatic approval review rejected a separate acceptance-server launch with
  only "blocked by policy". No alternate secondary launch bypassed it; visual
  acceptance used the already running main application and ordinary sign-in.

Ignored live evidence: data/security-review-live-20261021.json. No provider key,
vault contents, account passwords or raw user submissions belong in this file.
