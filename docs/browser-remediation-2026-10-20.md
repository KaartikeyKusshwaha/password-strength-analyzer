# Actual Edge remediation acceptance — 2026-10-20

Tested the existing signed-in owner's real workspace through Edge UI, using the explicitly disposable asset `Browser acceptance / code fixture` and no real credentials or production code.

Verified:

1. Assigned the previously observed PY001 fast-password-hashing finding to the existing owner. The Open column showed one task.
2. Started the task. It moved to In Progress with a success notification.
3. Submitted a corrected in-memory Python fixture at the same scope `browser-acceptance-password-hash.py`, replacing direct SHA-256 with scrypt and a random 16-byte salt. The scanner reported complete and zero observations. The UI explicitly limited coverage to eight Python AST rules and one submitted file.
4. Read the scan's displayed SHA-256: `508f10d0d5b8751aacdaca03bbe252c7d536cf11551120d2a4038fba37e73584`.
5. Submitted evidence describing precisely that fixture change, scan, hash, and coverage limitations. Task moved to Pending Review. The submitting owner was shown `Waiting for an independent reviewer.` with no approval control.
6. Reloaded the app and reopened Remediation. Pending Review remained one; Resolved remained zero. The original finding remained open, and the dashboard activity showed task submission, completed scan, and task start.

Evidence screenshot: `data/browser-acceptance-0.12.0/remediation-pending-review.png` (local, ignored).

Not verified: second-person reviewer approval/rejection, which needs a separately authorized reviewer account. No such account or access grant was created. No finding was falsely marked resolved. The companion's installed 0.12.2 unlock/save/fill verification remains separate and pending the user's extension reload.
