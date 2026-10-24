> Retired in app 0.18.0 at the user’s request. This document records historical behavior; current submission APIs and UI do not offer email/phishing detection.

# Message triage — 0.14.1

Users can submit message text or explicitly select an RFC 822 `.eml` message
from the control center or combined review. Control-center .eml attachments
select MIME parsing automatically. Other file contents use the selected format.
There is no mailbox connector, live inbox monitoring or automatic quarantine.

The local Python operator decodes subject and non-attachment plain/HTML body
parts. HTML scripts/styles/templates are excluded from text extraction. Both
multipart alternatives can be inspected; quoted or forwarded body text can
contribute indicators. Nothing is rendered as message HTML, and no URLs,
remote images, scripts or attachment contents are opened/executed.

Evidence consists of counts and fixed observations: urgency/credential requests,
obscured links, sensitive-data requests, exact From/Reply-To domain difference,
visible HTTP(S) label host versus href host, and executable/script filename
suffixes. Different reply domains and link hosts can be legitimate. A script
suffix does not establish malicious content. Display names, forged headers,
tracking redirects, relative URLs, CSS visual deception, archives, macros,
sender reputation and link destination contents are not validated.

SPF/DKIM/DMARC remain unverified even if Authentication-Results says pass.
Uploaded headers have no trusted receiving boundary. We never infer sender
identity or safety from these claims. No-indicator output is not a safe verdict.

Bounds: at most 15,000 input characters / 60 KB UTF-8; 40 MIME parts, depth 8;
30 HTML anchors and 30 text URLs. Embedded message/rfc822 content is skipped.
Undecodable, malformed, truncated or unsupported inline content appears as
unassessed, making scan and parent-review coverage partial. Invalid .eml input
fails; no silent reinterpretation as plain text is performed. Python's email
parser operates only on this bounded input; no external parser tools are run.

Raw input is kept only in existing ephemeral worker arguments. Stored coverage
has no body, subject, addresses, attachment names or URLs. Per-message SHA-256
scope stops unrelated messages from replacing each other's findings; identical
submissions reuse matching finding IDs. A digest reveals equality and may be
guessed for known content; it is not encryption or anonymous evidence. Legacy
message findings are retained. Reassessment does not resolve a finding by itself.

The optional agent sees only the existing allowlisted finding summaries, not
raw message text or coverage/header fields. Follow-up tasks remain proposals
for human work/review, not proof that a message is malicious or was blocked.

## assign-3 boundary

The upstream repository at commit bec3f83f47889f7f786f534fc19d04a18beddfc8
contains 40 curated/synthetic demonstration messages. Its TF-IDF/logistic
regression artifacts are not loaded into SentinelOps, and no training runs at
startup. No demonstration metrics or invented confidence scores are shown.
A validated corpus, artifact integrity/provenance, evaluation and operational
acceptance remain required for a learned classifier.

Source: https://github.com/KaartikeyKusshwaha/assign-3/blob/bec3f83f47889f7f786f534fc19d04a18beddfc8/model/dataset.py

## Verification

Regression cases cover decoded HTML/base64, header/body separation, forged
authentication claims, excluded attachments, redaction, exact-host differences,
ambiguous addresses, bad charsets/MIME, embedded messages, input/part limits,
per-message deduplication, invalid-format refusal and partial parent-review
propagation. React cases cover coverage rendering and approved format selection.
Actual inbox integration and trained classifier acceptance remain unfinished.


The full Python suite passed 394 tests before the final agent message-scope
adjustment. The final React suite passed 211 tests across 46 files, followed by
a successful production build. All 48 focused agent/platform/message regression checks passed after
the final scoping change. Existing unrelated Vite chunk-size and TestClient
deprecation warnings remain.

The local app upgrade preserved ten compared protected record groups, the
server encryption key, SQLite integrity and owner setup after an encrypted
backup. Actual Edge retained sign-in and visibly offered the explicit RFC 822
format in combined reviews. No fabricated message was inserted into the owner
workspace for this check. Runtime message/AI evidence uses isolated test stores;
real inbox/provider acceptance remains open. Ignored visual evidence:
`data/browser-acceptance-0.14.1/message-format.png`.
