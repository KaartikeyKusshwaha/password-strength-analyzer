# Secure-save expiry UX — incorporated in built companion 0.12.4

Update: this candidate was subsequently included in the 0.12.4 build alongside
the observed login classification fix. Full suite: 150 passed. Installed-browser
verification of the new expiry screen remains pending.

The actual 0.12.3 acceptance run exposed a confusing timeout: after a capture expired, its private window still offered Unlock and Encrypt and save login, requiring the user to discover expiry by attempting a save. The capture itself was correctly rejected; a fresh capture later saved successfully.

Source changes in vault-frame.jsx now:

- Count down from the worker's original capture deadline, rather than granting another three minutes when a window opens.
- Lock the SaveSession, discard the component's capture reference, remove unlock/save forms, and show clear close-and-recapture instructions when the deadline ends.
- Bound the expiry timer to at most three minutes after receipt and expire already-old/nonfinite deadlines immediately.
- Tell the user to check the dashboard if a save was already in progress; aborting a client request cannot prove the server did not commit it.

Focused verification: three new expiry tests and two existing native-crypto shared-save UI tests passed. Checks cover countdown, stale capture, expiry after unlocking, removal of captured identity and stale controls. This is not a claim of memory zeroization or a live browser verification of this candidate.

It was first built in a separate candidate directory while 0.12.3 remained installed. The dist/download archive has now been updated to 0.12.4 and a reload was requested. Exact-origin autofill acceptance remains pending the user's manual popup action; browser policy explicitly rejects extension-page observation and must not be bypassed.
