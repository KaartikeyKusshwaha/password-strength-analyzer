# macOS device helper pilot

The source uses the existing device pairing proof/code handoff, scoped loopback
polling and visible desktop UI. macOS stores the bounded device connection in a
single non-synchronizing generic-password item in the login Keychain using
Security.framework through pinned PyObjC bindings. No token is passed on a command
line or stored in a plaintext connection file. Locked or denied Keychain reads
fail explicitly. The Windows adapter retains current-user DPAPI storage.

Installation copies the packaged app into ~/Applications for this user only,
rejects escaping links and existing apps, and never replaces an existing bundle.
No sudo, login item, launch agent, system service or automatic startup is added.
Closing the window stops polling. Stop and forget waits for local read-only work
to finish before deleting only this helper's protected connection. Cloud device
revocation remains separate and must be performed in the extension.

Optional macOS posture v2 includes the application firewall, FileVault and
Gatekeeper through three fixed status-only commands. Unknown, localized,
in-progress, unavailable or failed output remains unassessed. No recovery keys,
serial numbers, process inventory or raw command output are uploaded. These
states are shown in the extension even when no scanner findings exist and flow
into optional Client Proof Pack posture. This is a self-report, not attestation,
patch compliance or a safe-device verdict. Cached Windows Update collection is
unavailable on macOS and its consent checkbox stays disabled. Legacy Windows
posture v1 remains unchanged; there are no new scanner rules.

The Mac builder requires native macOS, pinned PyInstaller/PyObjC/certifi and
bundles Python/dependency licenses. Its app uses bundled CA certificates for
frozen HTTPS, with certificate and hostname verification. Architecture-specific
ZIPs are ad-hoc signed by the build tooling only, not Developer ID-signed or
notarized. Do not disable OS protections to run a pilot. The download is shown
only when a matching packaged manifest/hash is installed on the service. An
unpublished source build is not advertised as a working download.

Native CI uses a standard GitHub-hosted macOS runner only for this public repo,
read-only repository permissions, no persisted checkout credentials, no caches,
no uploaded artifacts and no secrets. Tests create/delete a disposable Keychain
without changing the user's default/search-list keychains, then build and smoke
test the frozen app with the same disposable storage. This does not test the
normal login-Keychain prompt, installation UI or actual browser pairing. Those
remain in the final acceptance session on a real Mac. Windows installation and
pairing acceptance also remains outstanding after its shared UI refactor.

References: Apple generic-password Keychain services and PyObjC Security notes:
https://developer.apple.com/documentation/security/adding-a-password-to-the-keychain
https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains
https://pyobjc.readthedocs.io/en/latest/apinotes/Security.html
GitHub standard public runner billing:
https://docs.github.com/en/billing/concepts/product-billing/github-actions

Native run 39942415747 at commit 11c9b36 passed disposable-Keychain tests,
ARM64 app build and frozen-app storage/TLS self-test. No artifact was uploaded
or deployed. Initial run 39942145315 passed storage tests but failed building
because two upstream wheels omit licenses; verified matching-source license
copies are now bundled. Intel native build and normal desktop acceptance are
still unverified.

Final source run 39942791505 at 72b0e076 passed the ARM64 build, 29 native
tests (one Windows-only skip), and frozen disposable-Keychain/TLS self-test:
https://github.com/KaartikeyKusshwaha/password-strength-analyzer/actions/runs/39942791505
This revision also embeds Mac observations in the single-file device download.
No published binary, Intel build or normal desktop acceptance is implied.
