# OSV advisory severity — app 0.13.3

Manual dependency checks and registered watches use the same bounded OSV batch
matcher and detail lookup. No OSV API key is required. Names, ecosystems and
exact versions of the submitted pins go to OSV; source files and vault contents
do not. Range resolution, transitive dependency discovery and installed-software
discovery remain separate, unimplemented capabilities.

## Scoring and provenance

Valid OSV `severity` vectors are calculated with pinned `cvss==3.6` for CVSS 2.0,
3.0, 3.1 and 4.0. The complete vector must validate, including optional metrics.
Only its base metrics determine the displayed base score. Both base and reported
vectors are retained; optional threat/temporal/environmental scores do not get
mislabelled as base scores. Arbitrary `database_specific.severity` text is no
longer a substitute for a valid, attributable vector.

Each rating retains its matched advisory ID, version, base score, category and
optional record-declared source (`NVD`, `CNA` or `SELF`). The source declaration
comes from OSV data, not independent verification. Alias-only IDs that were not
queried do not invent ratings. Different source/version ratings remain visible.
The finding uses the highest available category, then score/version for ties.
CVSS 2 has no critical category; numbers across generations are not equivalent
risk scales. A zero score remains visible but does not clear an advisory match;
the existing finding vocabulary keeps its overall severity `unknown` for that
case. No score establishes local exposure, reachability or exploitability.

Package-specific severities use only the registered ecosystem/name. PyPI names
follow standard normalization. A sole matching package entry can be used after
the OSV batch match. Multiple matching entries require explicit membership of
the submitted version in `versions`; range applicability is not guessed.
Ambiguous entries are reported as ignored. Simultaneous global and package-level
severity fields conflict with the schema and are not used.

## Bounds and incomplete data

The existing 20-pin, 200-match, 20-detail-request bounds remain. A detail response
is at most 256 KB with an overall detail budget of 20 seconds. Each record uses
at most eight ratings and the UI retains at most 20 ratings per grouped match.
Malformed, withdrawn, missing, ambiguous and over-limit records cannot remove
the underlying batch match. Empty inventories make no request and claim no
assessment. Package matching, alias-detail lookup and CVSS coverage are separate.

Finding evidence shows `available`, `partial` or `unavailable` rating coverage,
usable/matched advisory counts, ignored entries and truncation. Check history
and watch runs report how many grouped matches have usable ratings. Missing
ratings stay unknown. Historical findings acquire current evidence only when
the user runs a new check; no old scan result is rewritten in place. Stable
finding IDs preserve task links and avoid duplicate new-match alerts when only
ratings change.

## Sources

- [OSV schema and severity fields](https://ossf.github.io/osv-schema/)
- [Red Hat Product Security CVSS library](https://github.com/RedHatProductSecurity/cvss)
- [FIRST CVSS 4.0 specification](https://www.first.org/cvss/v4.0/specification-document)
- [Python package name normalization](https://packaging.python.org/en/latest/specifications/name-normalization/)

Automated provider fixtures exercise calculations, malformed data, alias and
package scope, partial coverage, UI provenance, watch updates and task identity.
These are implementation tests, not an independent audit. Actual Edge visual
acceptance remains a separate check while local browser control is disabled.
