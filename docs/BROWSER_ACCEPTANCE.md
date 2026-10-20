# Browser acceptance — SentinelOps 0.12.0 / companion 0.12.4

Status: **partial live Edge verification**, 20 October 2026. Browser access now
works. The backend initially was not running and returned connection refused;
the existing local server was started successfully. Selected navigation, a real
local port-8110 assessment and a rerun of the public-package watch were verified.
A stale companion version label and mobile closed-navigation accessibility were
fixed, rebuilt and verified in Edge. Seven focused frontend tests passed.

Current hashes, screenshots and exact limits are recorded in
`browser-candidate-0.12.0-browser-check.json`; the prior candidate is retained.
This is partial acceptance, not certification of private vault or shared flows.
The user created a disposable Browser acceptance vault, and its dashboard unlock
was verified. Valuable existing vaults remain outside this run. Historical 0.9.2
observations remain in their original candidate record. Automated results in
VERIFICATION.md do not substitute for the remaining browser cases.

Latest results: the user confirmed encrypted saving through the 0.12.3 private
window; dashboard decryption, lock/reopen persistence and ciphertext-only payload
checks succeeded for the one disposable login. Archive preview/cancel, archive,
restore and encrypted account history also passed in the dashboard. See
`browser-save-persistence-0.12.3.md` and `browser-archive-restore-0.12.3.md`.
Autofill then failed: actual practice-page DOM labeled its login field
`autocomplete=new-password`. Companion 0.12.4 corrects that conflicting hint
only for explicit unambiguous sign-in forms and includes the expiry countdown.
All 150 frontend tests and production builds passed. Reload and actual fill
verification are pending; see `companion-0.12.4-autofill.md`.

Historical continuation before that acceptance: Edge reconnected and saved sign-in succeeded. The user
created the disposable Browser acceptance vault. Dashboard incorrect/correct
unlock was observed with zero entries, and a user-approved scoped companion
token was created. Save securely on the public practice login opened a blank
private panel in the installed, unversioned companion; no save was established.
Companion 0.12.1 added bounded startup diagnostics; 0.12.2 corrected a native-fetch
receiver error. The user subsequently supplied a successful popup-unlock
screenshot, but embedded saving still failed in the actual browser. Version
0.12.3 replaces embedding with a dedicated extension save window, binds captures
to that exact window/tab, removes public access to the private page/assets and
clarifies rejected-token reconnection. The user reloaded 0.12.3, and an actual
practice-site click created a private save window. Its unlock/save result needs
the user's observation because browser-control tools omit extension pages.
Never mark B06 passed from source tests, popup unlock or window creation alone.
Remediation and investigation checks are recorded separately in
`browser-remediation-2026-10-20.md` and `browser-investigation-2026-10-20.md`.

## Preconditions and private setup

1. In the ChatGPT desktop app, open **Settings > Computer Use**, enable your
   browser and check **Manage** for blocked websites. Confirm `127.0.0.1` is
   allowed. If connection state is stale, restart the browser and desktop app.
   This is the [documented setup path](https://learn.chatgpt.com/docs/chrome-extension);
   the prior generic “Work settings” instruction was imprecise. Codex announces
   browser-control attempts before accessing tabs.
2. Open the local dashboard at `http://127.0.0.1:8110/` and sign in yourself.
   Keep the sign-in password and authenticator codes in the app, not in chat.
3. In Chrome/Edge extension management, reload **SentinelOps Security Companion**
   and verify **0.12.4**. Load the **dist folder**, not its `assets` subfolder:
   `C:\Users\LENONO\Documents\Password-Strength-Analyzer\companion\extension\dist`.
   Internal extension-management pages may require the user's own clicks.
4. Use a user-created personal vault named Browser acceptance and only disposable
   test credentials. Choose its master passphrase privately. This is an isolated
   test vault inside the real product, not a fictional application workspace.
   Do not unlock, alter or export valuable existing entries for this run.
5. Pair that vault through Browser & devices. Enter the exact local app origin
   and freshly generated scoped token in the companion; grant its requested
   localhost permission, then unlock locally. Tokens and master passphrases must
   never appear in evidence, chat or screenshots.

The external [registration](https://practice.expandtesting.com/register) and
[login](https://practice.expandtesting.com/login) pages are provided for automation
practice and currently expose ordinary username/password fields. Their visible
page/form structure must be rechecked in the browser; a web fetch is not visual
verification. Do not submit an external registration or change an account until
the user chooses to do so. Use only disposable site credentials if submitted.

## Core browser run

Record browser/version, extension version, UTC time and case ID for each result.
Use `pass`, `fail`, `partial`, `blocked` or `not_run`. `partial` means specific
steps were observed but the full case has not been established. Unsupported is a truthful product
outcome to inspect, not permission to mark an unexecuted case passed.

Browser tooling redacts password values. Do not treat a returned masked value's
length or comparisons between masked values as evidence of actual password
length/equality, and do not bypass that redaction. Verify visible field filling,
the local estimate, no-submit behavior and user-reported confirmation separately.
Record the installed companion version before claiming that observed behavior
certifies the current packaged release. A local archive matching dist does not
prove which version is installed in the user's browser.

| ID | Action | Required visible result |
| --- | --- | --- |
| B01 | Open dashboard, visit core navigation and resize to a narrow window. | No blank page, overlapping controls, clipped approval text or inaccessible primary action. Empty states describe missing real data. |
| B02 | Pair the test vault; close/reopen the popup after its host-permission prompt. | Pairing persists; it opens Unlock rather than an unexplained pairing loop. No token is shown in clear text afterward. |
| B03 | Enter an incorrect test-vault passphrase, then the correct one. | Wrong value shows an error and exposes no entries; correct value unlocks only the paired vault. |
| B04 | Open the practice registration form, focus a password field and enter a disposable weak candidate. | The in-page assistant appears on the form and provides a local estimate. No separate password-lab page is necessary. |
| B05 | Generate a suggested password. | Recognized password/confirmation fields are filled consistently where supported. The form is never submitted and no account is claimed created. Unsupported constraints remain visible. |
| B06 | Select Save in my vault, unlock the test vault locally and approve saving. | Confirmation appears; dashboard sync shows one saved test login. Network evidence, if inspected, contains an encrypted envelope rather than its plaintext fields. Never capture authorization headers. |
| B07 | Close the popup and reopen the dashboard vault; lock and unlock it again. | The saved entry survives reopening. Locking removes visible credentials and hides private operator content. |
| B08 | Open the practice login page and explicitly select the saved exact-origin login. | Only the selected login is filled. No automatic submission or claim of successful login. An invalid disposable credential failing at the website is not a vault failure. |
| B09 | Open a different HTTPS origin and inspect the companion. | The saved login is not offered as a matching-origin login. It cannot be filled by selecting an unrelated website. |
| B10 | Save a new password for the same exact origin and username. | Explicit replacement confirmation is required. Cancelling retains the saved password. Accepted saving records a local save, not independent website-change verification. |
| B11 | Create a second personal test vault and save the same website with a distinct disposable password. Switch companion connections. | Switching locks the old vault. Unlocking the second gives its own entry/password; no cross-vault mixing or forced website uniqueness. |
| B12 | Set a restrictive website scope or disable browser filling for one test vault. Reopen/reconnect if the policy revoked its token. | Current policy is enforced. A denied/revoked connection produces an actionable error and cannot silently keep filling. |
| B13 | Select test entries in Account review, preview Archive, then cancel. Repeat with explicit approval. | Preview/cancel changes nothing. Approved archival retains encrypted data and moves entries into Archived view. No website account is closed. |
| B14 | Reopen/unlock the updated companion after archival. | Archived logins and authenticator entries are not offered for fills/codes or new password-change plans. Previously approved work cannot use an archived login. Old installed clients must not be used to certify this case. |
| B15 | Preview and approve Restore on one archived entry. | Only the selected entry becomes active and available according to its vault's browser permissions. History records archive/restore without old password values. |
| B16 | Approve a disposable account-change preparation plan and open it in the companion. | Selected scope survives popup reopening; a replacement is encrypted alongside the original. No external form is submitted. Unsupported forms show needs-attention. |
| B17 | Attempt to archive an entry with a pending replacement. Cancel/discard that proposal only if it was never used. | Archive is refused while recovery is pending; neither old nor staged secret is lost. Explicit discard retains the old login. |
| B18 | Hide the tab, wait for lock timeout, and revoke a test companion token. | Hidden/idle vaults lock; revoked connections cannot read or save. A late response does not reopen a locked vault. |
| B19 | Create an explicitly consented exact-pin dependency watch, choose Check now, and open its alert. | Queued/running/final states are truthful, package coverage is shown, and the per-user unread state updates. A provider failure is partial/unassessed, never a clean result. Pause before removing test setup. |
| B20 | Pair a disposable owned-device connection and run a small approved local/private TCP check. | Only allowed target/ports run, progress/results return to the central dashboard, and open ports are observations rather than proven vulnerabilities. Revoke the test connection afterward. |

## Additional release cases

Use a second separately authenticated **test** teammate for shared-vault cases.
Verify identity fingerprints through a trusted channel. Never use a real client's
vault as a permission-test fixture.

| ID | Action | Required visible result |
| --- | --- | --- |
| S01 | Invite/accept a shared vault, open in the dashboard and pair its companion scope. | Verified grant opens only the accepted vault; identity passphrase remains local. |
| S02 | Test a shared viewer and an editor in separate sessions. | Viewer can read permitted entries but cannot save, archive, review or prepare changes. Editor actions require preview/approval and obey browser policy. |
| S03 | Revoke a test recipient, rotate the shared key and retry the old companion. | Old grant/token cannot revive access; remaining members must open the current epoch. Cached copies cannot be erased and are not claimed erased. |
| S04 | Disable shared browser access, edit scope and test a stale save. | Current restrictions apply; stale changes cannot overwrite the current revision. |
| S05 | Open the app with one viewport around 390 CSS pixels wide and keyboard-only navigation. | Pair/unlock/approval errors and focused controls remain usable. Check actual layout rather than relying on DOM unit tests. |
| S06 | In a disposable shared-vault identity, change the sharing passphrase, then lock/unlock and re-pair. Test a second signed-in dashboard too. | Current keys/fingerprint and shared contents remain; new passphrase unlocks, old passphrase fails, own shared connections are revoked and unfinished shared actions cancelled. Personal/other-user connections survive. Other idle dashboard locks on its next identity poll. Wrong confirmation/current passphrase and stale conflicts do not replace protection. |
| S07 | Open personal/shared vault activity; page older events, refresh, lock and switch vaults. Remove a disposable teammate's access and refresh their activity. | Only current authorized vault records appear. No private account observations before unlock or after lock. Older service pages remain stable as new events arrive. Revoked reads show an error, never an invented clean history. Service records and bounded encrypted account observations remain separately labelled; no website-change proof is inferred. |
| S08 | With two disposable accepted teammates, propose ownership from the current owner and accept/decline from the addressed successor. Include a policy-change/reversal and a fresh successful handoff. | The central inbox opens shared review. No owner/key change before acceptance; invalidation cannot revive. Explicit acceptance preserves entries/staged recovery and other roles, applies the chosen former-owner access, changes the root/key epoch and revokes old browser connections. Remaining members verify the new owner. Workspace ownership remains separate. |

Cross-origin forms/iframes, ambiguous or hidden fields, custom/password-change
constraints and network races have automated tests, but require controlled
browser fixtures for full visual/browser claims. If no suitable owned fixture
is available, record that browser coverage as blocked. Passing the public
practice form alone does not certify compatibility with Google or all services.

## Evidence and cleanup

- Record the candidate archive/build hashes from `browser-candidate-0.12.0-browser-check.json`.
  A changed package invalidates prior evidence for the changed behavior.
- Keep screenshots limited to labels, states and masked fields. Do not include
  bearer tokens, master passphrases, recovery codes, seed keys or unlocked values.
- Record an exact failure trigger and actual result. A backend HTTP response or
  simulated DOM test cannot substitute for a visible browser result.
- Revoke test companion/device connections, pause test schedules, and archive
  disposable test vaults through the normal UI after the run. Retain evidence;
  do not delete real user data or silently reset any account/vault.
- Keep the production gates in PRODUCT_PLAN.md open: browser acceptance is not
  an independent cryptographic audit, recovery design, mobile/store release,
  production restore drill or universal website automation certification.
