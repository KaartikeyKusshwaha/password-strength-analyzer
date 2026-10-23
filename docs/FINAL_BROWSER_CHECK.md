# Consolidated final browser acceptance

This is the single planned live acceptance session, **not a passed checklist**.
No browser control was used to prepare it. Finish implementation and release
preflight first; native prompts, MFA and consent remain user actions when needed.
Use disposable accounts/credentials and retain no secrets in screenshots/logs.

## Before starting

- Pin one Git commit for backend, web and packaged extension. Record hashes and
  deployed version. Do not test the old Oracle release against unreleased source.
- Complete pending Client Proof Pack work. Weekly access reviews are in source
  and need enable/compile/sign-off, stale-evidence, next-batch and restart acceptance. Read-only
  background reminder polling is in source and needs alarm/restart acceptance. Atomic all-client-vault freelancer invitations, the expiry
  engine and extension controls are in source. Extension ownership transfer is now in source and needs this
  acceptance pass. External connector development is
  gated by three agency pain reports in the master plan; interviews are pending.
- Verify encrypted backup/restore and deployment health, HTTPS and free-resource
  limits. Oracle SSH was unavailable at the last preflight; deployment is pending.
- Use two separate browser profiles, two real disposable accounts, MFA, one
  client and two shared vaults. Keep only these tabs and the practice login page.
- Confirm the final extension package once; keep comparison codes and passwords
  within browser/extension surfaces. Do not publish screenshots containing them.

## One session, in order

1. Sign in/MFA, connect cloud Personal and both shared vaults using comparison
   codes. Check scope, expiry and revocation; disconnected grants must stop.
2. Exercise proactive login/signup invitations; generate and explicitly save a
   disposable login; reopen and fill its exact origin. Reject other origins and
   frames, and ensure closing the popup locks secrets. Test cloud TOTP explicitly
   with a disposable enrollment; it must never be disclosed to an AI planner.
3. Verify duplicate domains in different vaults stay separate; share with the
   second account, accept and read; edit/reopen; test both roles' restrictions.
4. Remove the second account through one approved two-vault offboarding run.
   Verify revoked tokens, inability to fetch new data, rotation to new keys and
   remaining-member access. Attempt decrypting a new payload with the old member
   key locally; retained copies of older data cannot be erased.
5. Run the supported credential queue on disposable entries: stage, stop/resume,
   preserve old/new values, explicit website submission, report results and retire
   shared-password debt. A login attempt or local save is not website acceptance.
6. Prepare a handoff; reject premature sign-off and stale evidence. Complete real
   ownership/removal steps, sign off as the receiving owner and inspect honest
   external-access/device exceptions and later changed-evidence warnings.
7. Exercise opt-in account discovery and consent disable; inspect that only
   approved domain/client/label metadata reaches the access map.
8. Execute final implemented freelancer/review/proof-pack paths with shortened
   test clocks in the isolated test deployment, then restore real timing. Verify
   approvals, expiries, alerts and reports without scanning external systems.
9. Install/pair the device helper through the extension on an owned test device.
   Check posture and allowed local checks, deny unapproved targets and revoke the
   pairing. Verify unsupported/helper-missing states are explicit.
10. Test recovery and a disposable restore; pre-restore grants and approvals must
    remain invalid. Check the normal four/five-item control-room navigation,
    disabled `/advanced`, no email/phishing remnants and mobile-width layouts.

Record each result as pass/fail/blocked with commit, profile, time and redacted
evidence. Any failure is fixed and its affected cases repeated; a single session
cannot guarantee that no retest will be necessary. Independent crypto/security
review, store approval, signing and design-partner validation remain separate
external gates, not results this browser pass can establish.
