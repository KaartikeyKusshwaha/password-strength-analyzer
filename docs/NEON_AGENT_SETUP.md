# Neon agent setup — 23 October 2026

Requested source: https://neon.com/.well-known/agent-skills/neon/SKILL.md.
The overview and relevant installed service skills were read. This record is
tooling setup evidence, not deployment or end-to-end service acceptance.

## Changes

- Installed the official `neon@latest` npm CLI globally; reported version 8.11.0.
- Installed nine project-local skills under `.agents/skills`: neon, neon-auth,
  neon-ai-gateway, neon-functions, neon-object-storage, neon-postgres,
  neon-postgres-branches, neon-postgres-egress-optimizer and neon-realtime.
  `skills-lock.json` records their sources/hashes and references are included.
- Configured the `Neon` MCP entry in the operator's existing Codex user config
  with OAuth and a project pin:
  `https://mcp.neon.tech/mcp?projectId=fragrant-glitter-21431406`.
  No API key was embedded. Existing node_repl and pika-mcp entries remain present;
  the resulting TOML parses. This session has not exposed a callable Neon MCP
  tool, so MCP authentication/connection is not claimed.
- Initialized an offline `.neon` pointer for organization
  `org-damp-queen-47948020`, project `fragrant-glitter-21431406`, branch
  `production`. The CLI explicitly reported that this link was not verified.
- Generated `neon.ts`, root `package.json`/`package-lock.json`, and `hello.ts`.
  The root npm dependencies are `@neon/config` and `@neon/env`; installation
  reported 22 packages added and zero vulnerabilities. The generated hello
  function is a placeholder, not a SentinelOps backend migration.
- The declaration includes Auth, private assets storage, Functions and Realtime.
  AI Gateway was removed after the user explicitly chose to keep free-only
  hosting. The installed AI Gateway skill says Free blocks its provisioning.
  Existing branches receive no branch-policy overrides.
- Added `.neon`, `.env.local` and `.env.*.local` ignores. Existing `.env` was
  privately backed up under ignored data before initialization; its SHA-256 was
  compared afterward and the bytes are unchanged. No environment values were
  printed or committed. Existing frontend/backend configuration was retained.

## Commands and results

Initialization used the requested org/project/branch and comma-separated
services, plus `--agent codex --mcp-auth oauth --mcp-project-scoped` to limit
tooling installation and avoid embedding credentials. PowerShell required
quoting the comma-separated services argument; the initial unquoted invocation
was rejected before setup and the quoted invocation completed.

The first `neon login` reported `Auth complete (profile DEFAULT)`. Credential
inspection reported OAuth and an existing account without printing credentials.
Both `neon config plan` and the read-only branch listing then failed with:

```text
The request could not be authorized due to an internal error
```

A second login was opened in the user's signed-in Edge profile. The standard CLI
consent asks for account-wide project/organization create/read/update/delete and
organization permission management. The user was asked to review/approve that
page; the agent did not approve it. The CLI then reported:

```text
Authentication timed out after 60 seconds
```

The user subsequently completed another CLI login in Brave. That attempt
reported `Auth complete (profile DEFAULT)` and exited successfully. The next
read-only project/plan requests still returned the internal authorization error.
An explicit `neon projects list -o json` then identified the access problem:

```text
not an organization member; org_id:"org-damp-queen-47948020"
```

The principal identifier is omitted here. No replacement organization/project
was created. Access requires an account belonging to the specified organization,
an owner-authorized membership grant, or corrected IDs supplied by the user.
Another login with the same account is not a demonstrated fix.

No Neon service apply/deploy, schema mutation, data migration, paid upgrade or
environment pull was performed. `npm run build` at the project root and live
end-to-end tests of the requested services remain pending actual integration;
the generated root package does not yet define a build command. Prior Render
container/PostgreSQL tests are separate evidence, not proof of Neon services.

## Resolved account setup and current state

The earlier paragraphs are historical checkpoints. After the user asked to use
their actual account without requiring them to locate IDs, read-only discovery
found exactly one workspace, `Kaartikey` (`org-lucky-pond-63419672`), on Free,
with no projects. Created `sentinelops-pilot` in `aws-ap-southeast-1`:

- Project: `round-butterfly-96197521`; branch `main` (`br-cold-rice-aoeomf6n`).
- PostgreSQL 18; project owner subscription `free_v3`; compute fixed at 0.25 CU.
- Updated the ignored `.neon` link and existing Codex OAuth MCP entry to this
  project; retained the other MCP entries. No further sign-in was needed.
- `neon config plan` and `neon deploy` succeeded. Deployed Managed Auth, private
  `assets` bucket, `hello` function and Realtime. AI Gateway remains undeclared;
  no paid upgrade was performed. Neon may create a default gateway credential
  on a project; it was not pulled or used for inference.
- Deploy pulled 12 managed variables into the existing ignored `.env`. All
  pre-existing application variable values were compared and preserved. Database
  TLS mode was then strengthened to `verify-full` for both connection strings.
- Windows libpq could not validate the connection with its system CA lookup.
  Using the existing HTTP client's certifi CA bundle fixed verification. The
  Psycopg adapter now supplies that bundle when no explicit root is configured;
  it still rejects hosted connections without full certificate/hostname checks.
- Created only the dedicated empty `sentinelops` schema (27 tables/schema 15);
  did not touch Managed Auth or other schemas. The application adapter validated
  the schema over both direct and pooled certificate-verified connections. No
  accounts existed in the new application schema.
- Generated persistent new-project MFA-encryption/bootstrap secrets privately in
  `.env` for the empty database. Existing local/Oracle key files were untouched.
- Added a root `npm run build` forwarding to the existing frontend and companion
  builds. It passed: frontend plus content, popup/vault-frame and background
  bundles. Existing large-bundle warnings remain; there was no build error.
- Started the actual application on loopback port 8112 using Neon and separate
  runtime data under ignored `data/neon-runtime-check`. `/api/status` returned
  HTTP 200 with `setup_required: true`; `/` returned HTTP 200. No user account
  was automatically created.
- Direct invocation of the deployed `hello` function returned HTTP 200 and the
  expected generated response; Managed Auth's public JWKS returned HTTP 200 and
  a keys array. These are infrastructure probes, not user-authentication tests.
- Added a pytest collection guard setting `DATABASE_URL` empty before dotenv
  loads, preventing legacy synthetic test fixtures from reaching the developer's
  real cloud database. Opt-in PostgreSQL tests retain their loopback-only fixture.

## Remaining service acceptance and cutover

The Python app uses the existing Psycopg driver. Managed Auth has not replaced
SentinelOps login; `hello` is still a generated placeholder, not a migrated
workflow runner. Private Object Storage upload/download and Realtime subscription
acceptance, user identity mapping and app integration remain unfinished. No
blanket claim that all provisioned services are wired into product flows is made.
Existing account IDs, owner/MFA/role controls and secret isolation must survive
any deliberate managed-auth integration.

Render deployment, final-origin extension/helper updates, old-data migration,
actual recurring off-server backup and consolidated browser acceptance remain
pending. The old Oracle VM, keys and retained archives are preserved; this new
empty database is not evidence that old vaults were migrated or recovered.
