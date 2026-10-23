# Render Free and Neon Free pilot

This is the selected free pilot target. It is not deployed or production-ready.
Oracle data, encryption keys, backups and the VM are retained until an actual
migration and restore/cutover check succeed. Do not initialize over existing data.

## Prepared implementation

- `render.yaml` requests one **Free** Docker web service, no disk, paid worker,
  Render database, upgrade or billing configuration.
- The Docker build compiles the existing frontend and companion, installs the
  pinned Python dependencies and runs the API as an unprivileged user. It has
  one process, retaining the existing runner and scheduler while awake.
- `.dockerignore` excludes local data, databases, keys, environment files,
  generated builds, dependencies, helper binaries and Git history.
- `DATABASE_URL` selects the PostgreSQL adapter explicitly. Connection failure
  never falls back to an empty local database. Hosted connections require
  `sslmode=verify-full`; retain the provider's certificate-validation options.
- PostgreSQL write transactions use a transaction-scoped advisory lock to
  preserve the existing one-writer approval/revocation/audit guarantees. Reads
  are read-only; statement integrity failures use savepoints. SQL translation
  applies only to the existing bounded application vocabulary, not user SQL.
- `APP_ENCRYPTION_KEY` must be a persistent Fernet key supplied as a deployment
  secret. It must be the existing key for an imported database, never a newly
  generated replacement. This is the server MFA encryption key; it does not
  decrypt client vault contents. New empty installations also require a private
  `BOOTSTRAP_TOKEN` of 32–128 characters. Neither belongs in Git or build args.
- `RENDER_EXTERNAL_URL` supplies the exact HTTPS origin unless `APP_ORIGIN` is
  explicitly configured. No wildcard trusted host or CORS relaxation is added.
- `deploy/postgres_schema.py` exports this release's empty schema only. It
  neither imports accounts nor changes any existing database. Schema creation is
  explicit and refuses a pre-existing schema; application startup validates the
  schema markers and column layouts instead of silently recreating tables.

## Deployment and migration gates

1. Sign in to Render and Neon through the browser. Keep both on Free; stop before
   any paid upgrade or billing flow. Create the dedicated Neon project/schema
   only after reviewing its account, region, access and no-cost settings.
2. Obtain a new encrypted, validated backup of the old application and its
   matching server MFA key. The retained 21 October backup is not evidence of
   the newest state. Never destroy the source after a failed export.
3. Prepare/validate the PostgreSQL import and export/restore tools. Preserve
   encrypted vault bytes, revisions, IDs, audit order and counters. Invalidate
   sessions, pending approvals and connection grants deliberately on cutover.
   **These data migration and PostgreSQL backup tools remain unfinished.**
4. Apply the empty schema to a dedicated database and import into that empty
   target in one validated transaction. Compare counts, payload digests, audit
   chains and constraint behavior. Do not use live customer credentials in tests.
5. Set private runtime secrets in Render, build the tested Git revision and
   verify the container/API startup. Docker and live Render deployment have not
   yet been exercised; local PostgreSQL tests do not establish those results.
6. Set the final cloud origin in the companion/helper build, publish a distinct
   version, pair to the new host and perform FINAL_BROWSER_CHECK.md. Existing
   builds still default to the old Oracle hostname; no new hostname is guessed.
7. Verify a fresh PostgreSQL encrypted export and isolated restore before
   declaring cutover. Keep Oracle intact until rollback and data preservation
   are proven. Remove temporary diagnostic access separately from deleting data.

## Free-tier behavior

Render Free sleeps after 15 idle minutes and can restart. The next extension or
web request wakes it with a delay. Background checks, weekly reviews and expiry
workers cannot execute while the service sleeps. No keep-alive traffic is used
to evade this behavior. Do not claim timely unattended revocation or monitoring;
an external reliable scheduler/worker is a separate future deployment decision.
The existing persisted runner can resume appropriate work after startup, but
interrupted raw-input scans still need explicit re-submission. No queued raw
source or plaintext vault contents are added for hosting convenience.

Neon quotas and sleeping behavior are independent. Quota exhaustion or an
unavailable database must fail requests explicitly, never create an empty vault.
This free pilot is for acceptance/testing; it is not a promise of availability,
timely offboarding, independent audit or production suitability.

Sources checked 23 October 2026:
- https://render.com/docs/free
- https://render.com/docs/disks
- https://neon.com/blog/neon-free-plan-1-gb-per-project
- https://www.psycopg.org/psycopg3/docs/basic/install.html

## Local evidence

An isolated password-protected PostgreSQL 15 test server listens only on loopback
port 15439. The initial empty schema has 27 tables and 212 application columns.
Tests exercise schema constraints, rollback, concurrent audit writers, workspace
isolation, setup/login, two-vault offboarding, local rotation, MFA/last-owner
guards and cancellation. Hosted startup/restart/secret checks are recorded in
the current verification folder. All fixtures are synthetic; no application
account/vault has been imported. SQLite remains the default for existing local
installations; PostgreSQL must be selected deliberately.

Verification on 23 October 2026: 53 schema/store/application/provenance/release
tests passed against the isolated PostgreSQL server, including access-map and
Proof Pack generation; 28 existing SQLite login/MFA tests also passed. These
checks do not establish Docker, Neon, Render or browser acceptance. The only
warning was the existing Starlette test-client dependency deprecation.
