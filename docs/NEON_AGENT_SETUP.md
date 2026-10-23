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

## Next action

Resolve the organization membership or supplied IDs first. If changing accounts,
run `neon login` and promptly complete its browser authorization with the account
that can access the specified project. Then retry the read-only plan, confirm
the project's region and no-cost availability of the remaining services before
any apply. Keep the existing Psycopg driver for the Python backend. Do not
replace existing SentinelOps identities or send vault secrets to a new provider
as part of a tooling installation. A managed-auth integration needs deliberate
account-ID mapping and the existing role/MFA/security boundaries preserved.
