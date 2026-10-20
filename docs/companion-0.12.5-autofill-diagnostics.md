# Companion 0.12.5: dynamic forms and autofill diagnostics

On 20 October 2026 the user again reported that clicking did not fill the
practice login. Their screenshot showed SentinelOps' new-password suggestion,
not its saved-login popup. In a connected Edge tab, refreshing the practice
login and focusing its password field reproduced the suggestion. Read-only DOM
inspection confirmed one editable password input named/id password with
autocomplete=new-password, an editable username, same-origin /authenticate
action and a visible Login submit button. No saved passwords were extracted.
The installed companion version could not be established from that screenshot.

The content script previously classified a field only while attaching its focus
listener. If a login button became available later, that listener could still
open a new-password suggestion. Focus now rechecks the current form. Fields
that become registration fields are also handled; obsolete suggestions close
after form mutations. Password generation checks the form again at click time.
This is a reproduced UI symptom and a verified source timing defect; it does
not establish the cause of every installed autofill failure.

The popup now checks the content version and supported target in frame 0 before
accessing an entry for transmission. An absent/stale receiver or unsupported
password/username/action gets a specific error. Filling repeats target checks,
refreshes vault policy and observes the existing session-generation guard.
Unknown failures never claim success. Permission scopes, exact HTTPS origins,
same-origin actions, top-frame restriction and no-submit behavior remain.
Both the popup header and suggestion show the companion version.

Tests cover late login controls, changing field classifications, stale panel
closure, version mismatch, receiver absence, locked sessions, rejected targets,
preflight without DOM mutation, form changes after preflight and real shared
vault decryption/policy revocation. These tests do not prove installed-browser
autofill. Browser tooling does not expose extension popup controls; the user
must reload the existing unpacked extension, refresh the practice page and
observe its Fill this login result. No new pairing or grant is required.

Verification: all 162 frontend tests across 38 files passed; both companion
production builds succeeded. The regenerated ZIP matches all 12 build files
byte for byte and the manifest has no web-accessible private resources.
The app build remains 0.12.0; only the companion release changed to 0.12.5.
Local reproduction screenshot (ignored runtime evidence):
data/browser-acceptance-0.12.0/login-assistant-reproduced-before-0.12.5.png.
