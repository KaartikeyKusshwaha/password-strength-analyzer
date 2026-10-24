# Installed companion unlock and private save — 2026-10-20

User supplied a screenshot showing `Unlocked · this popup only` after reconnecting. This proves an installed popup reached its unlocked state. The screenshot does not identify the selected vault, extension version, or a saved entry; those are not inferred.

Actual subsequent Edge test:

- Opened the published practice login at https://practice.expandtesting.com/login and filled its public demo credentials, as previously approved. Did not submit Login, register, or change a password.
- Installed content assistant displayed local password assessment.
- Clicked Save securely from the assistant.
- Extension-owned embedded save area remained blank, then the watchdog reported `The private extension panel did not start. No login was saved.`
- This is a confirmed remaining failure, separate from the fixed native-fetch receiver issue. Correct pairing/unlock did not resolve it. No successful save or autofill is claimed.
- The practice site's own advertising overlay also appeared; it was dismissed. No browser security warning was bypassed.
- Scoped web-tab logs exposed no startup error; they do not establish extension-frame health. Need further extension startup/message or embedding diagnosis.

Unbuilt source improvement prepared separately: rejected companion requests carry a stable CONNECTION_INVALID code; popup discards local unlock material, hides the unusable passphrase form, and offers explicit re-pairing. Unknown legacy vault names are labeled unverified rather than assumed Personal, and labels include the service port. Focused reconnect, fetch and shared-UI tests: five passed. Installed dist/archive remain 0.12.2 and have not been replaced during the user's pairing attempt. Further changes must be built/versioned before requesting another reload.
