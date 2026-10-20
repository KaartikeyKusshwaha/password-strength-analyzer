# Dependency watch alias grouping (development)

Implementation and isolated frontend candidate are tested in the worktree.
The running 0.12.0 process and its frontend build have deliberately not been
replaced while private browser acceptance setup is pending. This document does
not claim that the new capability has passed live dashboard acceptance.

## Behavior

An exact-pin watch first sends its approved package names and versions to the
fixed OSV querybatch endpoint. That endpoint returns IDs, not full records.
The worker then requests at most 20 unique IDs from the fixed OSV detail
endpoint. It rejects redirects, a mismatched record ID, withdrawn records,
malformed aliases and oversized records. No provider URL or instruction is
executed, and no LLM is involved.

Records that share returned alias IDs are grouped transitively within the same
exact package/version. Every originally matched ID and the reported alias union
are retained in the finding. The dashboard exposes those IDs and shows detail
coverage separately from package assessment coverage. No severity is inferred
from an ID or alias. A missing detail record does not remove its original match.

The request budget is 20 seconds between detail requests/chunks, with a
three-second HTTP timeout. An in-progress request may take its timeout beyond
the budget. Each decoded record is capped at 256 KB; at most 100 valid aliases
per record are accepted. Existing batch package, response and result limits
still apply. No automatic pagination, retries or arbitrary hosts are added.

If a later run reports another ID in the same known alias group, persistence
retains an existing finding ID, first-seen time and linked task within the same
asset, scan scope and exact package. New grouped matches create at most one new
task per finding when automatic task creation was explicitly enabled.

## Limits

- Alias relationships come from OSV records; this is neither independent
  advisory validation nor proof of exploitability.
- Detail failure/limits can leave overlapping raw matches. A complete package
  match query can have partial alias-detail coverage; the UI states both.
- Historical findings/tasks are retained. Grouping does not silently resolve,
  delete or consolidate existing work or its review history. A historical
  overlapping finding can become unobserved in the latest scan without being
  declared fixed. Partial detail coverage can still produce duplicate work.
- This implementation enriches dependency watches. One-off dependency scans
  retain their existing query behavior. Severity enrichment, installed software,
  transitive graphs and external notifications remain unfinished.

## Evidence

Automated checks cover transitive grouping, package/version separation,
cross-watch persistence separation, stable IDs and tasks, malformed/mismatched/
withdrawn records, redirects, oversized records, request caps, network failure
and missing legacy UI metadata. A live read-only OSV probe for public
`npm lodash@4.17.20` returned five matches and five valid detail records. None of
those five matched records overlapped with one another; each exposed its CVE
alias. That probe did not write the user's application database.

Primary API documentation:
- https://google.github.io/osv.dev/post-v1-querybatch/
- https://google.github.io/osv.dev/get-v1-vulns/
