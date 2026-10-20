# Companion 0.12.4 — observed login classification fix

The user reported Fill this login did not work. The permitted browser screenshot showed empty fields. Read-only DOM inspection of the public practice login established: type=password, id=password, name=password, autocomplete=new-password, action=https://practice.expandtesting.com/authenticate. No password value was inspected.

The old content handler excluded every field classified as new-password, including this actual sign-in field. The revised classifier overrides that conflicting autocomplete hint only when the form has exactly one password input, a visible editable username/email input and a visible submit control explicitly labeled Login or Sign in. Registration/change/reset URL paths and explicit new/confirmation field names retain their existing protections. Unknown or ambiguous forms remain unsupported.

The deterministic fill logic is now a small testable module. It still requires exact HTTPS origin and same-origin form action; denies ambiguous password/username fields, disabled/read-only fields and confirmation inputs; dispatches normal input/change events; never submits. The content receiver now explicitly rejects subframes in addition to the top-level-only manifest injection. Invalid credential shapes are rejected before DOM mutation. No browser permission, token scope or origin match was broadened.

The release also incorporates the previously staged save-expiry countdown, removal of stale controls, capture-reference disposal and close/retry guidance.

Verification on 2026-10-20:

- Actual field metadata was inspected through the visible practice input's DOM attributes, not inferred from a source fixture.
- Five new fill tests cover that shape, no submission, signup/change exclusions, hidden/ambiguous controls, HTTP/sibling/lookalike origin denial, foreign actions, and disabled/read-only fields.
- Full frontend suite: 150 tests passed across 36 files.
- Companion and dashboard production builds succeeded. Existing large strength chunk warning remains.
- Download archive regenerated. User asked to reload 0.12.4 and retry manually.

Installed-browser fill success, unrelated-origin denial and extension-side archived-entry handling remain unverified. Source tests do not establish those results. Browser security policy blocks observing/controlling extension pages; no bypass is permitted.
