# Companion 0.12.2 — installed browser verification pending

The user's popup screenshot showed `Failed to execute 'fetch' on 'Window': Illegal invocation` while unlocking. SaveSession stored native fetch as an instance property and invoked it as a method, giving it the session as receiver.

The default transport now calls globalThis.fetch on its global object. Requests invoke injected transports without binding the session. No encryption, origin matching, permissions, or token scope was relaxed.

Verification on 2026-10-20:

- Receiver-sensitive regression reproduces the browser's exception with the previous implementation and succeeds with the corrected transport.
- Custom transport remains unbound; expired-connection handling and request cleanup checked.
- Frontend: 137 tests passed across 33 files.
- Companion and dashboard production builds passed; existing large strength bundle warning remains.
- Built manifest and download archive updated to 0.12.2.

Pending: user reload of the installed extension, popup unlock of the selected disposable Browser acceptance vault, encrypted save and exact-origin autofill tests. This source/build verification does not establish installed-browser success. Screenshot selected Personal vault; select Browser acceptance before using its disposable test passphrase. Revoke the scoped test connection after testing.
