# Personal login portability

In an unlocked personal vault, open **Move logins to another password manager**.
Review the selected count and explicitly approve downloading plaintext passwords.
The CSV uses `name,url,username,password` columns for Chrome-style importers.
All values are quoted, quotes are doubled, and records use CRLF separators.
Exact credential values, including Unicode, commas and embedded newlines, are
preserved. Destination importers may impose additional limits.

Only this vault's current saved login fields are exported. Archived logins are
excluded unless selected. TOTP secrets, notes, account history, pending proposed
passwords, recovery/sharing keys and vault properties are excluded. Duplicate
origins and usernames remain independent rows. Shared-vault export is not added.
Use the encrypted backup for a complete recoverable copy.

Export runs in the browser using a Blob and a short-lived object URL. There is no
export API, provider call or AI request. Approval clears after download request,
selection changes, vault-content replacement or locking. Locked vaults have no
plaintext export controls. A download request does not prove the file was saved.

The resulting file is unencrypted. Keep it private, import directly into the
destination manager and remove it when no longer needed. Do not open it in a
spreadsheet. Prefixing formula-like values would corrupt exact passwords, so
CSV quoting is structural escaping, not spreadsheet formula protection.

Automated checks cover exact import/export round trips, archive selection,
excluded secrets, local Blob creation/cleanup, consent invalidation, download
failure reporting and the parent vault's lock/reunlock lifecycle. Actual browser
download and a third-party manager import remain unverified; no real personal
credentials were exported during development.
