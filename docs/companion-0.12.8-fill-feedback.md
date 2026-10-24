# Autofill feedback — companion 0.12.8

The user reported another actual Edge fill failure. Page control is now
available, but not the toolbar popup. The two practice fields were observed
empty and their DOM matches the existing supported sign-in fixture. Backend
contact metadata reports 0.12.7. Only the disposable test vault was checked
locally; its master works and its public practice credentials are correct.
There is no verified root-cause or successful installed-fill claim yet.

Previous errors appeared only at the top of a potentially long popup. The new
client displays progress and outcomes beside the selected entry. While busy,
its button says Filling and prevents another fill. Stages distinguish form
preflight, current vault access and waiting for a field-retention receipt.

Page messages now have five-second acknowledgement deadlines. An unanswered
preflight cannot cause the vault to release credentials. An unanswered fill
does not cause another send or claim nothing was filled: the original message
may have arrived. The user is told to inspect the fields before retrying.
The vault request still has its existing separate timeout and access checks.
No credentials, tokens or native messaging exceptions are put in diagnostics.

Tests cover stage order, missing receivers, no credential access after failed
preflight, one send after an uncertain fill, inline visible refusals and receipt
success. Existing real-form, controlled-input, origin, policy and retention
tests remain. These are automated tests, not installed-browser acceptance.

Acceptance needs a reload to 0.12.8, a practice-page refresh and a click on Fill
this login from the connected, unlocked Browser acceptance test vault. The
browser driver must inspect both actual field values and the popup's result;
it must not fill the fields itself or submit the website to manufacture proof.
If still failing, record the exact stage/error and fix that observed path.
