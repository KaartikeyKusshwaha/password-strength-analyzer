# Extension-first acceptance ledger

This ledger separates implemented behavior from release acceptance. A checked
unit test or deployed archive does not prove an installed extension workflow.

| Requirement | Current implementation | Remaining evidence / work |
| --- | --- | --- |
| Site check starts and finishes in extension | Browser-only exact-origin header operator, plain guidance | Installed permission / badge acceptance |
| Device checks in extension | Scoped helper operator, progress, results, cancellation | Installed helper pairing and complete cloud scan |
| Python and dependency file checks | Popup paste/drop, inventory preview, selected OSV disclosure, results | Native popup file-drop acceptance |
| One assistant surface | Internal pipeline hidden; device/project controls collapsed in popup | Product usability review with real users |
| Signup/password-change suggestions | Trusted-focus local generation and explicit secure save | Login/signup invitations directly observed on practice site; content 0.21 versus popup 0.22 mismatch needs reload synchronization |
| Login and TOTP assistance | Exact-origin login choice, explicit linked TOTP fill, no submit; installed login invitation observed | Installed cloud multi-vault acceptance; unattended TOTP is not implemented |
| Post-login save offer | Per-site opt-in, trusted standard login submission, ephemeral worker draft, explicit private save | Native navigation/expiry acceptance; no universal success detection or locked-vault duplicate detection |
| In-page popup launch | Toolbar popup works by user report; invitation is visible | Programmatic popup launch still fails in active Edge practice tab; diagnose native error before calling complete |
| Quiet background site checks | Per-origin opt-in, alarms, local results, badges, opt-out | Real Chrome/Edge alarm lifecycle |
| Password health in popup | Local weak/reuse estimates; on-demand and opt-in daily-on-unlock padded HIBP prefix checks | Installed host-permission/lock cancellation acceptance; no always-on checking while locked |
| Approve account fixes without website | Popup selection creates encrypted plan; existing operator stages/prepares forms; stop action available | Native popup claim, form preparation and resume acceptance |
| Add authenticator without website | Parse setup key/URI locally, policy checks, ciphertext write; code shown in popup | External service must confirm first code; native popup acceptance |
| Control-room website | Vaults, Security results, Connections, Settings; advanced panels collapsed; primary run/add buttons removed | Four destinations and current onboarding copy rendered in signed-in Edge 0.21; subsequent native acceptance still needed |
| Cloud sign-in connection | Proof-bound code comparison and scoped approval, no token copying | Real cloud grant + popup acceptance |
| Multiple and shared vaults | Existing per-vault encrypted data, scoped tokens and shared trust checks | Personal/shared token-free handoff implemented; complete multi-vault browser run |
| Device onboarding | Bundled per-user Windows helper with short-code pairing and account reauthentication | GUI install, shortcut, uninstall and live extension pairing |
| No phishing feature | Email operator, MIME module and MAIL rules removed; new inbox assets excluded | Rejection regressions and independent audit of exposed entry points |
| Independent review | Threat-model/security docs and automated authorization tests exist | An external security audit has not occurred |

No universal password-change API, arbitrary-command agent, unattended website
submission, automatic OS repair, passkey-to-vault unlock, or email breach
monitor is claimed. A browser cannot inspect device ports without the helper.
The helper remains an unsigned pilot. These limits must remain visible rather
than being hidden behind a success status or a completion percentage.

### Queued HTTP-response correction

Source review found that error responses carrying the expected security headers
could produce an empty action list. The queued checker now requires a 2xx
response before interpreting headers. Access-denied, unsupported HEAD,
rate-limited and unavailable responses remain unassessed. A real-checker monitor
regression verifies that a 503 with all expected headers retains the unknown
badge. All 29 site-check/operator/UI/monitor tests passed. This correction is
source-only; the installed 0.22 directory and archive remain frozen.

Edge reconnected as browser 4. The practice login invitation appeared after
trusted focus; evidence is saved under ignored data/oracle-deployment as
edge-reconnected-login-invitation.png. The Personal cloud vault remains at its
initialization form, with no passphrase entered. Native popup site-check
acceptance still awaits the user's click.
