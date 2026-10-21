# Extension-first acceptance ledger

This ledger separates implemented behavior from release acceptance. A checked
unit test or deployed archive does not prove an installed extension workflow.

| Requirement | Current implementation | Remaining evidence / work |
| --- | --- | --- |
| Site check starts and finishes in extension | Browser-only exact-origin header operator, plain guidance | Installed permission / badge acceptance |
| Device checks in extension | Scoped helper operator, progress, results, cancellation | Installed helper pairing and complete cloud scan |
| Python and dependency file checks | Popup paste/drop, inventory preview, selected OSV disclosure, results | Native popup file-drop acceptance |
| One assistant surface | Internal pipeline hidden; device/project controls collapsed in popup | Product usability review with real users |
| Signup/password-change suggestions | Trusted-focus local generation and explicit secure save | Additional production-site compatibility checks |
| Login and TOTP assistance | Exact-origin login choice, explicit linked TOTP fill, no submit | Installed cloud multi-vault acceptance; unattended TOTP is not implemented |
| Post-login save offer | Per-site opt-in, trusted standard login submission, ephemeral worker draft, explicit private save | Native navigation/expiry acceptance; no universal success detection or locked-vault duplicate detection |
| Quiet background site checks | Per-origin opt-in, alarms, local results, badges, opt-out | Real Chrome/Edge alarm lifecycle |
| Password health in popup | Local weak/reuse estimates; opt-in padded HIBP prefix checks while unlocked | Installed host-permission/lock cancellation acceptance; periodic breach monitoring is not implemented |
| Approve account fixes without website | Popup selection creates encrypted plan; existing operator stages/prepares forms; stop action available | Native popup claim, form preparation and resume acceptance |
| Add authenticator without website | Parse setup key/URI locally, policy checks, ciphertext write; code shown in popup | External service must confirm first code; native popup acceptance |
| Control-room website | Vaults, Security results, Connections, Settings; advanced panels collapsed; primary run/add buttons removed | Four destinations, Connections and Settings rendered in signed-in Edge; newest onboarding copy needs acceptance |
| Cloud sign-in connection | Proof-bound code comparison and scoped approval, no token copying | Real cloud grant + popup acceptance |
| Multiple and shared vaults | Existing per-vault encrypted data, scoped tokens and shared trust checks | Personal/shared token-free handoff implemented; complete multi-vault browser run |
| Device onboarding | Bundled per-user Windows helper with short-code pairing and account reauthentication | GUI install, shortcut, uninstall and live extension pairing |
| No phishing feature | Excluded from exposed workflows and new operators | Historical unused scanner functions remain; verify no exposed entry point in audit |
| Independent review | Threat-model/security docs and automated authorization tests exist | An external security audit has not occurred |

No universal password-change API, arbitrary-command agent, unattended website
submission, automatic OS repair, passkey-to-vault unlock, or email breach
monitor is claimed. A browser cannot inspect device ports without the helper.
The helper remains an unsigned pilot. These limits must remain visible rather
than being hidden behind a success status or a completion percentage.
