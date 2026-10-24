# Companion 0.12.3 — secure save window

The installed companion's private iframe stayed blank and failed its startup watchdog after successful popup pairing/unlock. The exact embedding failure was not established through the available web-origin browser diagnostics. This release removes the dependency on embedding the credential-entry UI in a website.

Save securely now requests a dedicated extension-owned popup window. It does not submit the website's form. The worker keeps the capture in memory for at most three minutes (worker suspension may end it earlier), creates one fixed private URL, and releases the capture only to the exact created window's top-level tab. A page starting before window creation resolves waits for verified IDs. Different windows, tabs, subframes and expired/superseded requests are denied. Closing that window clears its worker capture. The old unscoped popup capture retrieval was removed.

No secret is placed in the window URL, webpage status or acknowledgement. Only a random capture request ID is in the private URL. The private save page and chunks are no longer web-accessible resources. The existing SaveSession still encrypts locally and enforces live server policy before writing. No network permissions were expanded.

Also: invalid tokens lock popup material and replace the unusable unlock form with a reconnect action. Older connections lacking a verified vault name are labeled unverified, not Personal; labels include the service port.

Verification:

- Full frontend suite: 141 tests across 34 files passed before the final missing-window-binding guard.
- Final focused worker suite: eight tests passed, including malformed binding, startup race, sender/window/tab/subframe denial, expiry, close, failed create, duplicate-open prevention, superseded requests, and no secret in page acknowledgements or persistence.
- Companion and dashboard production builds passed. Companion rebuilt again after the binding guard; zip regenerated. Existing large strength chunk warning remains.
- User confirmed reload to 0.12.3. The actual practice login assistant created the secure window and displayed the instruction to finish there.
- Remaining: private-window rendering/unlock/save confirmation, dashboard persistence, exact-origin fill and unrelated-origin denial. Browser tools omit extension pages, so the private-window observation is requested from the user. No completed save is claimed yet.

Reference: https://developer.chrome.com/docs/extensions/reference/api/windows
