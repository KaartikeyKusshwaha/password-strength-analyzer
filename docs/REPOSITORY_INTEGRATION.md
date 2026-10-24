# Repository integration and agent scope — 22 October 2026

Source review of the public main branches and current SentinelOps implementation
distinguishes rebuilt capabilities from importing each original engine. These
are current-state findings, not claims that all source repositories were merged.

| Original repository | Current SentinelOps path | Remaining integration |
| --- | --- | --- |
| Password-Strength-Analyzer | Local in-page checks, generated passwords, encrypted personal/shared vaults, explicit saves and selected-origin fill. | Installed compatibility across sites, mobile/store distribution, independent review, native offline-kit recovery acceptance and shared-identity recovery. |
| vulnerability-scanner | `backend/device_checks.py` provides selected TCP observations; `backend/scanner.py` checks allowlisted HTTPS headers. `backend/posture.py` and the paired operator add fixed Windows status probes. App 0.15.0 also adds separately consented Windows Update cache/restart observations, not a full patch inventory. OSV exact-pin watches add sourced CVSS records. | No full installed-software discovery, service fingerprinting, vulnerability reachability proof or general autonomous remediation. Original hardcoded banner-to-CVE matching was not adopted as proof of vulnerability. |
| assign-3 | Retired at the user's request. No email-detection operator, MIME extractor or MAIL rules are included in the current source. | No inbox, phishing classifier or mail connector is planned in the active product scope. Historical results may remain readable; they cannot start new email checks. |
| assign-4 | App MFA, replay-aware TOTP verification and encrypted external-account TOTP storage have Python implementations. | The original Node app is not embedded or called. Provider-side enrollment remains necessary. Vault seed storage alone cannot enable another service's MFA. Hardware/device and broader enrollment acceptance are unfinished. |

## Actual automation

The control center can run one scoped assessment, persist findings and optionally
start the AI remediation planner. `backend/agents.py` uses one Groq planner plus
deterministic evidence, citation, task-dispatch and progress workers. It validates
evidence freshness and per-run write permissions. Current tasks and investigation
records are tracked; a task is not execution of a device repair. Credentials,
vault contents and raw source submissions are excluded from provider input.

The new user-supplied Groq credential is stored only in ignored local `.env`.
The configured Llama model was unavailable to this account; a model-list request
authenticated successfully. The configuration was explicitly changed to the
available `openai/gpt-oss-120b`, without a runtime fallback. A live plan passed
schema/citation validation. A separate isolated synthetic API operation then ran
the actual Python check -> Groq planner -> task dispatcher -> progress flow:
one finding, one task, all five worker steps complete, audit valid and progress
awaiting_recheck. Raw source was not retained. The main app was backed up and
restarted with protected-record comparisons passing. This establishes the
tested workflow, not arbitrary repair execution or real-owner browser acceptance.
Ignored evidence: data/groq-live-acceptance-20261021.json,
data/groq-workflow-live-20261021.json and data/groq-config-result-20261021.json.

## Product differentiation to finish

The intended audience remains small teams and agencies with client accounts.
Per-client vault access, offboarding, device posture, dependency
advisories and an evidence-backed remediation workflow should form one outcome.
Password saving/autofill alone is feature overlap with established managers.
No claim of superior cryptographic safety or browser reliability is supported by
the present development evidence.

A cross-module review coordinator is now implemented in 0.14.0. It previews and
approves up to six scoped checks, aggregates their finding IDs and runs one
optional AI/task pass. A live synthetic API case passed with two modules, three
findings and three tasks. Actual Edge acceptance also verified a localhost port/posture review, explicit partial coverage and one live AI-created task. This is
aggregation and scoped execution, not independent risk correlation or the entire
autonomous remediation loop.
Per-site password-change adapters, safe device remediation, explicit account
connectors and recovery need separate implementation and real acceptance.

## Reviewed sources

- [assign-3 README](https://github.com/KaartikeyKusshwaha/assign-3)
- [assign-3 predictor](https://github.com/KaartikeyKusshwaha/assign-3/blob/main/model/predictor.py)
- [assign-4 server](https://github.com/KaartikeyKusshwaha/assign-4/blob/main/server.js)
- [vulnerability-scanner engine](https://github.com/KaartikeyKusshwaha/vulnerability-scanner/blob/main/scanner/core.py)
- [Google Password Manager overview](https://support.google.com/chrome/answer/6208650?hl=en)

The Google documentation lists generation, storage, passkeys, autofill and
compromised-password assistance. Those features alone are not a distinct market
position for SentinelOps. Our workflow differentiation is a product direction;
unfinished integrations must remain labelled as unfinished.


## Extension-first implementation as of companion 0.22.0

Normal site/device/Python/dependency checks start in the extension and return
progress, observations and action drafts there. The website is a four-section
control room, with operational detail under Advanced. The current extension
also provides proactive generation, opt-in ephemeral login-attempt save offers,
exact-origin login/TOTP filling, authenticator setup, password health, encrypted
account-change approvals and personal/shared cloud handoff without token copying.
A bundled optional Windows helper pairs using a short code; it does not give a
webpage access to arbitrary device commands. Recurring password-dataset checks
are opt-in per vault and run only on a due unlock, with bounded rotating batches.
They do not retain unlock keys or send passwords to AI. Native cloud-vault,
shared-user and helper acceptance and independent security review are still
required. See EXTENSION_ACCEPTANCE.md for the current evidence ledger.
