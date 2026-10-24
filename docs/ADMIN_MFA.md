# Administrator MFA enrollment

The default application configuration requires account authenticator enrollment
for workspace owners and accepted shared-vault owners/administrators. The policy
checks current roles across the user's workspaces, not a cached role in a browser
session or bearer. There is no database or encryption-format migration.

An existing administrator without MFA can still sign in, sign out, view account
security/passkeys, enroll an authenticator, and read/manage their encrypted
personal vaults, review personal-vault activity and revoke their own companion
connections. Workspace endpoints return HTTP 428 until enrollment succeeds.
The web app shows enrollment before loading the workspace snapshot or approving
an extension connection. It retains the one-time recovery codes on screen until
explicit continuation, rather than navigating away immediately after setup.
Codes and setup material are not saved to browser storage or sent to agents.

Enabling MFA uses the existing password-confirmed draft, expiry, TOTP verification,
single-use recovery-code hashing and session revocation. It does not generate a
substitute factor or silently enroll the user. Existing MFA accounts continue to
use their existing login challenge. An administrator cannot disable MFA until
all administrative roles have been transferred or removed. Cached vault data
cannot be erased remotely by this gate.

Existing shared-vault, assessment, discovery and device connections recheck the
policy. Personal vault bearers retain their existing scope. Access-workflow
bearers already require owner MFA independently. Scheduled watches, review
workers, operations and AI jobs check live enrollment before work/dispatch or
recording results. A paused or failed old job requires the existing explicit
resume/retry path; enrollment does not replay it automatically.

`Settings(admin_mfa_required=False)` is a programmatic compatibility override for
isolated legacy feature tests. The normal app entry point uses the mandatory
default; no environment variable disables it. The dedicated policy tests use
the production default or simulate rolling it out over existing grants. Do not
interpret the older fixture's deliberate override as evidence of policy coverage.

This is account MFA, not vault decryption or external-service MFA enrollment.
No vault keys are made available to the server. Browser acceptance, independent
review and deployment remain separate gates. The policy is source implementation
until an explicitly verified release is deployed.
Deploy the matching web build and backend together; an older web build does not
contain the enrollment screen.

## Verification checkpoint

- Backend `tests/` checkpoint: 470 passed, one skipped; the root analyzer suite
  separately passed all 16 tests. One existing Starlette deprecation warning remains.
- After the final worker and personal-access guards, 49 focused policy, platform,
  device and activity regressions passed. The final six default-policy regressions
  passed again with the additional stored-device bearer assertion.
- Frontend: 374 passed across 82 files. The web production build passed.
- Policy cases cover enrollment/login, protected workspace access, personal vault
  access/activity, shared-admin role changes, stored shared/security/discovery/device
  tokens, preexisting workers, permission loss before planning and MFA loss between
  planning and dispatch. Legacy feature fixtures explicitly use the compatibility
  override; the policy tests exercise the default or a rollout over old grants.
- Browser acceptance and a new Oracle deployment were not performed.
