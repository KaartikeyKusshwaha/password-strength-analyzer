# Windows device helper pilot

The extension starts and displays device checks. The optional Windows helper
executes the existing deterministic TCP, posture and cached-update operators
on the user's own computer. It has no vault access, LLM execution, arbitrary
command interface, administrator elevation or automatic repair capability.

## User flow

1. In the companion security assistant, open Connect device helper and download
   the Windows app. Its version and SHA-256 are shown alongside the download.
2. Open the app. Choose the optional read-only protection/update checks and
   click Install and get pairing code. This installs for the current Windows
   user and adds a Start menu shortcut and Windows uninstall entry. Python is
   bundled. No startup service, firewall exception or scheduled task is added.
3. Enter the helper's eight-character code in the extension. Review its exact
   loopback/optional tool scope, then approve with the SentinelOps account
   password and an unused MFA/recovery code when enabled. Credentials are sent
   to the connected SentinelOps service for reauthentication, not to AI or the
   helper, and are not saved in extension storage.
4. The helper automatically receives its device-only connection and stores it
   using current-user Windows DPAPI. The extension refreshes its device list.
   Start checks in the extension and read their results there.
5. Keep the helper window open while checking. Closing it stops polling. Start
   it again from the Start menu when needed. Revoke cloud access in Connections;
   uninstall locally using Windows Installed apps. Uninstallation does not
   silently claim to revoke cloud grants.

Existing assessment-only extension grants cannot pair devices. Disconnect and
reconnect security agents to approve the additional pairing capability. The
sign-in approval page explicitly lists this capability; older pending requests
and approval clients default to no device-pairing permission.

## Authorization and storage

Requests expire after five minutes. The short code identifies a pending helper
request; it is not a bearer token. A separate random 256-bit proof stays in the
helper process. Only proof-bound polling receives the encrypted handoff.
Approval requires current workspace membership, explicitly authorized pairing
access, account reauthentication and MFA when enabled. Scope changes and replay
are rejected. Pairing creates a thirty-day device-only grant for 127.0.0.1 and
::1, with each optional tool separately consented. Cancelled handoffs revoke
their grant and interrupt its pending operations. Backup restore removes
handoffs and device grants. Revocation/offboarding prevents further device work.

Device tokens use current-user DPAPI, with no machine-wide flag. This protects
stored tokens from other users; it does not protect against a compromised
Windows account or malicious software running as that user. No plaintext
connection JSON is written by this flow. Connection proofs are not put in URLs.

## Build and acceptance limits

Build on Windows with Python 3.12 x64, install
`companion/helper-build-requirements.txt`, then run
`python -m companion.build_helper`. Build outputs under `companion/helper-dist`
are ignored by Git and explicitly included in the deployment archive. The
manifest records artifact digest, version, size, builder and source digests.
Python and PyInstaller licenses are bundled.

This is an unsigned pilot installer. Windows may show publisher/security
prompts; SentinelOps does not disable or bypass those protections. The compiled
headless self-test checks operator import and a real DPAPI round trip without
installing software, creating a cloud grant or scanning the device. Automated
tests also cover proof binding, account MFA/replay, scope restrictions, legacy
grant isolation, cancellation and restore invalidation. Installed GUI, shortcut,
uninstall and real browser-to-helper acceptance are separate pending checks.
An independent security review remains required before production use.

Sources: [Microsoft DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata),
[PyInstaller usage](https://www.pyinstaller.org/en/stable/usage.html).

Before advertising the Windows pilot download, the backend now verifies its
actual SHA-256 against bounded, unlinked metadata as well as size/platform.
Deployment packaging rechecks the exact helper payload bytes against metadata
for both Windows and macOS. Changed bytes make the download unavailable or
packaging fail; a checksum is not code signing, an independent security review
or proof of a source-matching rebuild. Installed helper 0.1.0 remains the older
pilot artifact until a deliberate current-source replacement is prepared.
