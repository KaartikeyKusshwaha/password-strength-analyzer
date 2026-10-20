# Actual Edge investigation acceptance — 2026-10-20

Used the disposable `Browser acceptance / code fixture` finding in the existing owner's workspace through the visible browser UI.

- Selected only PY001 and created `Browser acceptance / code review` with an explicitly disposable opening note.
- Verified one linked observation and correct opening note, actor, and timestamp.
- Attempted to close the case while its finding was unresolved. The application rejected it with `Resolve linked findings through reviewed tasks first` and retained the edit form.
- Changed status to Investigating with a truthful progress note; saved successfully.
- Followed the linked finding and verified its scope, line 3 evidence, and `Not observed in the latest check of this scope. Resolution still requires evidence and review.` The original finding remained Open.
- Evidence & activity showed Links Verified and the expected investigation.created, investigation.updated, task.submit, scan.completed, task.start, and task.created events. No independent signing or external retention is implied by this display.

Screenshots (local ignored evidence): `data/browser-acceptance-0.12.0/investigation-verified.png` and `activity-verified.png`.

No real incident was declared; no external communication, security grant, or finding resolution was performed. A subsequent read-only Windows protection assessment was launched through Control center; its outcome must be recorded separately after completion.
