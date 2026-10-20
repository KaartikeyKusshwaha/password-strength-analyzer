# Live backend recovery and connection status

On 20 October the user authorized direct testing with the established disposable
Browser acceptance vault. Edge was connected, but the available browser inventory
had no native desktop surface. Extension management and toolbar popup controls
remain outside the exposed browser API; additional user permission does not
make those controls available. No extension-page or desktop bypass was attempted.

## Observed and corrected

1. A refreshed public practice login still opened the older unversioned
   password assistant. Companion 0.12.5 includes visible version text which was
   absent. Installed 0.12.5 acceptance and saved-login autofill remain unverified.
2. The open dashboard claimed Workspace connected, but unlocking the test vault
   failed with Cannot reach SentinelOps. There was no Python process or listener
   on 127.0.0.1:8110. An encrypted operator backup completed with the existing
   separate key; the local single-worker server was started hidden. SQLite
   quick_check returned ok and the schema remained 8.
3. The actual dashboard subsequently unlocked Browser acceptance and decrypted
   its one saved public practice login. The Personal vault was not unlocked.
   The public demo password's live HIBP hash-prefix lookup completed and reported
   1,763 occurrences. This is a dataset observation at that time, not a claim
   about a private user's account. The test vault was locked afterward.
4. The unconditional connected label was replaced with a status derived from
   the latest app request. Network errors, server errors and invalid JSON show
   separate unavailable/error states. Expected authorization responses still
   establish that the backend responded. Retry makes only a read-only /status
   request: failed writes are never replayed. This is not a continuous health
   certificate; the existing alerts poll also updates it every 15 seconds.

## Browser verification

The rebuilt app was served and loaded in Edge. Temporary request blocking was
limited to this dashboard tab's own /api/ URLs; it produced an actual failed
vault-activity request and Backend unavailable with Retry connection. Clearing
the rule and clicking Retry restored Backend reachable; refreshing activity
then removed its fetch error. No server-wide outage or vault mutation was needed.

An initial generic offline simulation and exact-text waits did not establish a
result. A fresh snapshot showed that the status also contains the Retry button;
the final test waits for that actual control instead. The subsequent complete
failure/retry sequence passed. All request rules/offline overrides were cleared.

At 390 by 844 the outage warning and retry remained visible. Document width was
375 versus a 390-pixel viewport, with no horizontal overflow. Retry recovered,
and the normal viewport was restored. The vault remained locked. Local ignored
screenshots in data/browser-acceptance-0.12.0:

- live-breach-check-public-login.png
- backend-unavailable-indicator.png
- backend-recovered-indicator.png
- backend-unavailable-mobile.png

## Automated and dependency checks

All 165 frontend tests across 39 files passed. The production dashboard build
succeeded; the existing strength-estimator chunk warning remains. Tests cover
real client network failure/retry, server/invalid-response errors, authorization
responses and preserved same-origin credentials/CSRF. The final responsive-only
markup/CSS adjustment was rebuilt and verified in the browser.

An installed-environment pip-audit found advisories only for pip 25.0.1. Updating
the project's virtual environment installer to 26.2.1 completed. A second strict
audit covered 57 packages and reported zero known advisories; pip check passed.
Reports are ignored local runtime artifacts, not uploaded user data. Application
dependency pins did not change. This advisory lookup is not an independent audit.

No new authentication credentials, token grants, provider account changes,
external form submissions or shared-vault permissions were created. Existing
test companion grants remain for the still-pending extension acceptance run.
