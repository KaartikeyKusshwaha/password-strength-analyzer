# Dependency inventories — app 0.17.0

The control center, focused checks, combined reviews and watches accept:

- Unconditional `name==version` Python requirements. Conflicting versions in this
  format are rejected; ranges, includes, URLs and markers are not resolved.
- Exact dependency/dev/optional/peer versions in `package.json`.
- npm `package-lock.json` or `npm-shrinkwrap.json`, lockfile versions 2 and 3,
  using their packages map. Workspace links and nonstandard registry sources are
  explicitly unassessed. Multiple versions of a package stay separate.
- `uv.lock` version 1, revisions 0–3, for packages with an explicit standard PyPI
  registry source. Editable project roots are counted separately. Git, local and
  private-index sources are unassessed.
- A normalized JSON inventory with a `packages` list of exact
  `{ecosystem,name,version}` objects. Watch editing uses this format to preserve
  version variants instead of collapsing names into a dependency map.

## Review before external disclosure

`POST /api/dependency-inventory/preview` requires authentication, CSRF and write
permission. It parses in memory without OSV calls or retained source files.
The React preview lists exact version identities, lets the user exclude private
names, and clears approval on source/selection changes. Standard registry metadata
does not prove that a name is public. Names and versions are potentially private.

The backend reparses the submitted source and validates the selected stable IDs.
Manual checks and operations require `dependency_consent`; imported lockfiles
also require an explicit selected list. Watches use their separate `consent` for
metadata retention, provider disclosure and any enabled recurring checks. Original
file contents, paths, source URLs and project names are not retained in results.
Normalized selected identities and coverage counters are retained as evidence.

Editing a watch uses its registered exact scope, not the original project file.
Reimport the original file to reassess project-level exclusions or unsupported
records; the normalized representation cannot reconstruct omitted records.

## Bounds and coverage

An inventory permits 1 MiB UTF-8 input, 10,000 source records and 500 unique exact
package/version pairs. Approved dependency-capable API routes permit a 3 MiB
JSON request envelope only after session/CSRF verification. Other routes keep
their existing 160 KB body limit. Reviews permit 1 MiB aggregate source input;
Python and email retain their smaller individual limits.

OSV batch queries send at most 50 selected versions per request, with a 60-second
batch budget, an eight-second request timeout, 1 MB response per batch and 4 MB
aggregate response limit. Up to 200 matches and the existing 20 advisory detail
lookups are processed. If a later batch fails, prior completed version coverage
and matches remain. Paginated or malformed results remain incomplete. No provider
substitution or invented safe result is used.

Source exclusions, unsupported records, version-query coverage, advisory-detail
coverage and severity coverage are separate. Watches retain source gaps on every
run, even when every selected package query succeeds. Such results stay partial.

Lockfiles can include development, optional and platform variants that are not
installed on the current device. This process does not execute installers,
resolve a runtime dependency graph, verify tarball integrity, discover installed
software, prove reachability, or certify that a project is safe. Raw source and
vault secrets are excluded from the optional existing AI planning workflow.

Format references: [npm lockfile documentation](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/),
[uv universal lockfile](https://docs.astral.sh/uv/concepts/projects/layout/#the-lockfile),
[OSV batch-query ordering and pagination](https://google.github.io/osv.dev/post-v1-querybatch/).

Automated checks cover real project lockfile parsing, private-source redaction,
variant preservation, stale selection rejection, provider-free preview,
permission boundaries, watch persistence and partial batch failure. Installed
browser acceptance is a separate check; passing unit tests does not imply it.

## Actual Edge acceptance — 21 October 2026

The existing owner session loaded app 0.17.0. File upload initially required the
browser extension's file-URL permission; after the user changed that setting,
the actual frontend lockfile imported and previewed 205 versions. Registering
`SentinelOps frontend lockfile` left recurrence and automatic tasks disabled.
Its live OSV check assessed 205/205 versions, with zero returned matches. The
normalized watch editor preserved all 205 versions; editing was cancelled.

A separate control-center check selected only hash-wasm 4.12.0 from three real
project package records. Changing selection cleared disclosure approval. The
result assessed one version and correctly retained a partial status for the two
excluded versions. No safe-project conclusion was inferred.

An actual combined review checked localhost TCP 8110 and the full 205-version
lockfile. Both assessments and the single Groq planning workflow completed. The
planner included its one port observation and linked one existing task rather
than duplicating it. No external password changes or device settings changes
were performed. A port observation is not proof of vulnerability; zero advisory
matches does not certify safety. This does not establish native acceptance for
shared vaults, recovery kits or all other product workflows.
