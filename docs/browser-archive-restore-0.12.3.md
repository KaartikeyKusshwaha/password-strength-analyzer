# Disposable login archive/restore browser acceptance

Actual Edge dashboard checks on 2026-10-20, restricted to Browser acceptance and the public practice login:

- Verified the selected vault label before unlocking with the existing disposable test passphrase.
- Selected only the practice entry, opened Preview archive, cancelled it, and verified the entry remained visible in Active.
- Reopened the exact-selection archive preview, approved it, and verified the encrypted-save success notice. The entry disappeared from Active.
- Selected Archived and verified the same origin/username remained recoverable with Archived status.
- Previewed and approved Restore, then returned to Active. The entry reappeared; the restore plan was no longer displayed.
- Opened its encrypted account history: First saved, Archived, and Restored events were displayed, with no old password values.
- Left the dashboard locked and reopened a fresh empty public practice login tab for the manual extension-popup fill step.

Screenshot: `data/browser-acceptance-0.12.0/demo-login-restored-0.12.3.png`.

These establish the dashboard parts of B13/B15 for one disposable personal-vault login. They do not establish the installed companion's archived-entry rejection (B14), shared-role behavior, or external account closure. No website account, password, or MFA configuration was changed.

Browser boundary: the original practice tab was absent from the current inventory. The inventory now included the extension save page, but browser acquisition was explicitly rejected because only HTTP/HTTPS protocols are allowed. No alternate browser surface, raw CDP, indirect execution, or other workaround was attempted to observe that blocked page. The user must operate the extension UI; permitted dashboard and public-site tests can continue independently.
