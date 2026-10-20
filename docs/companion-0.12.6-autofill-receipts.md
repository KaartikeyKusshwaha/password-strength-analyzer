# Companion 0.12.6: observed field retention

The 0.12.5 autofill implementation returned success immediately after setting
values and dispatching input/change events. A website handler could replace a
field, change the destination, or clear a controlled value while the companion
still reported success. This source defect does not establish the cause of the
user's earlier installed-browser failure.

The 0.12.6 content receiver revalidates the exact form and field identities
between writes and after input handlers. It refuses to write the password if
the username handler changes the target. After a bounded 150 ms observation,
it checks that the same eligible fields still contain the intended values.
No credential write is retried and no form is submitted. A website can change
values later; this receipt is not provider acceptance or a successful sign-in.

The asynchronous extension reply contains only an outcome and whether both
fields or just a password field were filled. It never returns credential values
to the popup as diagnostics. The popup distinguishes password-only steps,
reports field replacement/value rejection, clears old notices and prevents
overlapping Fill clicks. Existing main-frame, exact HTTPS origin, form-action,
version, fresh vault policy and session-generation checks remain in place.
There are no new permissions or web-accessible private resources.

Verification on 21 October 2026:

- 28 focused tests passed across five files, including a real React controlled
  form, immediate destination changes, field replacement, queued value reset,
  password-only receipts, unchanged no-submit behavior and shared-vault policy.
- Full frontend suite: 189 passed across 41 files. Tests use simulated browser
  messages/DOM where applicable; they do not certify an installed extension.
- Both companion production builds passed. The regenerated archive matches all
  12 build files byte for byte. Manifest version is 0.12.6; permissions remain
  storage and activeTab, with no web-accessible private resources and no frames.
- Archive SHA-256:
  41a130e3c1f912e3a900eb97fe5860dddaa7182fbf970099659ba651b419943a

Live acceptance is still open. The current control inventory reports no apps
or browsers and local browser use disabled in Work settings. The agent did not
reload the installed extension or bypass that access restriction. Reloading the
existing unpacked companion and refreshing the practice login are still needed
before its version and field-retention result can be observed in actual Edge.
The previous test pairing and public demo login remain unchanged.
