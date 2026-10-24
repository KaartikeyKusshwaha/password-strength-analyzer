# Quiet site checks

Companion 0.18.0 adds optional browser-local header monitoring. It does not
monitor email, read vaults, inspect page content or upload browsing history.
It is separate from cloud assessment grants and requires no cloud login.

In the popup, Quiet site checks lets the user enable the current exact HTTPS
origin. Host access is requested on that click, not for every website. Up to
50 chosen origins are stored locally with their latest result/time; page paths,
query strings, page titles, credentials and visit logs are not stored. The
worker ignores visits to sites that are not explicitly opted in. Content
scripts cannot enable monitoring or read the chosen-site list; only the
extension popup can manage it.

Visits reuse checks for twelve hours. An alarm wakes roughly every thirty
minutes and checks due origins in batches of five concurrent requests. Successful
checks are due after twelve hours; failed checks can retry on a later visit or
alarm after fifteen minutes. Browser sleep, shutdown and service-worker limits
can delay work. This is best-effort browser automation, not an always-on hosted
monitor or an exact-time SLA. Startup/install events recreate the alarm when
chosen sites exist. No alarm is kept when the list is empty.

Each check sends one HTTPS HEAD request to the chosen origin's root, omitting
cookies, referrer, page paths, query strings and request bodies. It does not
follow redirects. It observes HSTS, CSP and content-type protection headers,
using the same operator as the manual popup check. Header presence is not
correctness, and a hostname's syntax is not proof of its resolved IP or a site's
safety. This is not authenticated-page analysis, exploitation, crawling,
breach monitoring or an ownership-verified cloud scan. Failures stay unassessed.

The per-tab badge uses ! for header observations and ? for an unassessed check.
Pending private-save badges take priority. Results appear in the popup's site
check, and an explicit Check this site refreshes the saved monitoring result and
badge. Navigation clears stale tab badges. Disabling a chosen site removes its
saved result and stops future checks; completing in-flight work cannot restore
that opt-in. Removing its browser host permission removes the monitoring entry.
Disabling monitoring alone retains host access that may also serve autofill;
users can separately revoke that access in browser extension settings.

The worker is built as an additional IIFE bundle by `npm run build:companion`.
Packaging rejects an alarms-enabled manifest with the unbundled worker source.
Run `node companion/verify_worker.cjs` after building to boot the actual bundle
against isolated API fixtures; this is not real browser acceptance. Source tests
cover no opt-in/no requests, exact scope, cache/rechecks, permission removal,
in-flight opt-out, failure state, badge priority and bounded scheduled concurrency.
Installed Chrome/Edge alarm lifecycle and permission/badge UI remain unverified.

Implementation follows the [Chrome alarms API](https://developer.chrome.com/docs/extensions/reference/api/alarms)
and [extension service-worker lifecycle guidance](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle).
