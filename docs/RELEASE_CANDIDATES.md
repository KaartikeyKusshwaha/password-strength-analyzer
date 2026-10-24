# Matched-source release candidates

Use the existing pinned frontend dependencies and Python environment. Prepare a
new disposable directory, leaving installed web/extension builds untouched:

```powershell
.venv\Scripts\python.exe deploy\prepare_release.py --destination C:\PrivateBuilds\SentinelOps-candidate
```

The destination must not exist and its parent must already exist. The command
builds the web app, content script, popup and background worker into this new
directory, validates/packages the companion, records source/output hashes and
creates `sentinelops-release.tar.gz` with `candidate.json`. Four builds must all
succeed. Source or Git revision changes during preparation fail the candidate.
No live database, environment file or operator key is copied. Installed build
directories are not targeted. Failed partial candidates remain for inspection
and may be consolidated with generated test files; do not install them.

The build record binds the exact generated output inventory to the current
source digest and Git HEAD. The deployment packager refuses missing/stale records,
changed output, missing assets and a changed Git revision. It also checks the
bytes read into the archive against the recorded output hashes. Source includes
backend, frontend entry/source/dependency lock, companion and deployment code.
Tests, documents, private data, environments and generated build files are not
inputs. Uncommitted source edits are represented by their source digest; HEAD
alone is not a claim that the worktree is clean. Commit before making a final
shipping candidate. Build records are locally generated assertions, not signed
publisher attestations or proof that the source is safe.

Release archives now contain `build-provenance.json`; the archive inventory
includes its checksum. An older independently prepared build without this
record cannot be packaged by the updated tool. Do not manually stamp an old
frontend to bypass the matched-build requirement. The fixed optional backup
templates and available helper artifacts remain separately allowlisted.

This command does not bump versions, replace an installed extension, publish a
GitHub/store release, migrate a database, deploy, sign a helper, activate backups
or pass browser acceptance. Source candidate extension versions may still equal
the previous prerelease until a deliberate versioned release is prepared. Never
overwrite an already published version with candidate bytes. Final release
requires a new version, complete required checks, backup/rollback review and the
consolidated browser/device acceptance record. See FINAL_BROWSER_CHECK.md.
