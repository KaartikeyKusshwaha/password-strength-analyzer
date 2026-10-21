# Extension-first transition

The extension is the intended primary product. The website is the control room
for vault administration, saved results, connections and account/team settings.
Normal credential and assessment workflows must return their result inside the
extension. A dashboard shortcut is not equivalent to this requirement.

## Implemented first increment

Companion 0.14.0 adds a public-site header check directly in the popup. Access is
requested on an explicit click for the active exact origin, not all websites.
The extension rechecks that origin after permission approval. It sends one HEAD
request to the origin root without cookies, referrer, query/path, request body,
redirect following, page text or credentials. HTTP pages receive an address-only
warning without a network request. Browser-internal URLs, numeric IPs, localhost,
local-name targets and nonstandard ports are excluded from this operator.

Results show bounded header observations and plain actions in the popup.
Missing headers are not proof of exploitability. Failed/redirected requests have
no safety verdict. Site header repair requires the site's owner; this version
does not offer a fake automated repair or declare arbitrary websites safe.
No cloud account, vault unlock, Groq call or website allowlist is needed for this
browser-local check. Device checks still require the existing scoped helper.

The web sidebar exposes its four primary destinations and puts the existing
operational panels under a collapsed Advanced section. The web landing opens
vault management. Legacy task routes remain available under Advanced while
their replacement extension workflows are implemented.

## Remaining implementation and acceptance

1. Proactive exact-origin login assistance, TOTP form handling and post-login save
   offers, with explicit secret-use controls and navigation/iframe protections.
2. A unified assistant in the popup for approved cloud/device/code/dependency
   operations, short progress and actionable output; no arbitrary LLM commands.
3. Optional background header rechecks for explicitly opted-in origins and
   privacy-preserving local vault health checks; no browsing-history upload.
4. One-time cloud authorization without manual tokens. Vault-only connection
   credentials must not silently gain workspace or scanner permissions.
5. A reviewed device-helper installer/native-messaging flow with short-code
   pairing, exact scope and revocation. No hidden installation or broad port scan.
6. Complete all remaining normal tasks inside the extension, simplify the web
   landing, and finish cloud personal/shared multi-vault and helper acceptance.
7. Independent security review. Automated tests and an author review do not
   replace an external audit.

Passkey vault unlocking is optional future work. Phishing detection is excluded.
The local 0.14.0 build alone is not evidence that an installed browser extension
has reloaded or that native permission prompts and actual-site checks have passed.

## Verification, 21 October 2026

The first full frontend run passed 259 tests and exposed one initial-context
message regression. That message was changed from an error to a normal status
hint; the affected popup regression passed afterward. The final focused run
passed 22 tests, including exact-origin permission, denied access, navigation,
cookie/referrer exclusion, unavailable checks, HTTP-only warnings, reconnect and
vault-first navigation. Python packaging/status/deployment checks passed 24 with
one native Windows symlink fixture skipped. React and companion builds passed.

The hosted UI was updated with hash-verified archives after an encrypted backup.
Prior frontend/package files were retained. Public HTML references the new
vault-landing bundle. Browser control became disabled before rendered acceptance;
the installed 0.14.0 popup and its real-site permission flow remain unverified.
