# Built-extension Playwright checks

This is an automated Chromium test layer, not installed Edge/cloud acceptance.
The real content, popup and service-worker bundles are loaded into a new,
disposable persistent browser profile for each case. Existing browser profiles,
cloud accounts, vaults, grants and operator secrets are not used.

## Run

```powershell
npm --prefix frontend ci
npm --prefix frontend run build:companion
npm --prefix frontend exec -- playwright install chromium
npm --prefix frontend run test:extension
```

Linux builders additionally use `playwright install --with-deps chromium`.
The Playwright dependency is pinned in the frontend lockfile. Chromium's
`chromium` channel supports headless extension loading; this does not side-load
into the user's installed Chrome or Edge. See the
[official extension testing guide](https://playwright.dev/docs/chrome-extensions).

The fixture uses synthetic HTTPS pages at `login.sentinelops.test`. Document
responses are fulfilled by Playwright before external DNS/TLS, and other routed
page requests are aborted. The fresh extension has no saved grants, configured
cloud connection or opted-in background monitoring. Routing does not claim to
intercept all service-worker/browser-internal traffic. Tests do not click cloud
connect, request host permissions, log into a real service or run a scanner.
Only disposable literal fixture credentials/codes are used. No TLS-validation
relaxation or modified extension manifest is used.

## Cases and limits

| Case | What it proves |
| --- | --- |
| Worker and popup startup | The real MV3 worker starts and the extension popup renders its cloud-connect view without an account. |
| Exact-origin login fill | An actual worker-to-content message fills the fixture username/password and receives an acknowledgement; the form is not submitted. |
| Wrong-origin/unsafe action | Another-origin credentials and a form posting to another origin are rejected; fields remain empty. |
| Signup/embedded forms | Signup fields and a login confined to an iframe are not selected as a main-page sign-in form. |
| Explicit code fill | A requested fixture code reaches the single supported exact-origin OTP field without submission. This does not test enrollment or a real TOTP secret. |
| Agency approval and progress | The real popup prepares a two-vault offboarding plan against a routed mock service, sends approval credentials once, polls queued/running/completed states and opens the scoped report. Only the fixture service reports completion; this case does not perform real revocation or key rotation. |

The agency fixture stores only a disposable workflow token in its isolated
browser profile. Its API route handles CORS preflight and blocks all non-fixture
destinations. This is not a connection to the Render installation. Real
removed-member/new-epoch cryptography and durable execution are separately
exercised in backend CI, rather than inferred from a mocked browser response.

The tests wait for the installed content-script version before sending an
operation, and never retry a credential write. Vitest remains scoped to `src`
so it does not collect the separate Playwright suite. Results go to ignored
`data/extension-e2e-results`; the workflow uploads no browser profile or trace.

## Verified result — 24 October 2026

[CI run 40010876391](https://github.com/KaartikeyKusshwaha/password-strength-analyzer/actions/runs/40010876391),
commit `bc2521925aa758046a0b273cc7f3e9eb1d7ab7ae`: **5 passed in 5.9 seconds**
on Linux with the built companion 0.25.0. The same run passed 73 PostgreSQL/backup
checks (one platform skip), 41 helper/release checks, clean Docker build,
non-root packaging and isolated API/frontend startup.

The local Windows run failed before all five cases because Chromium could not
be spawned (`spawn UNKNOWN`); it is not recorded as a local pass. No installed
browser permissions were changed to bypass that failure. Linux CI is the actual
passing browser evidence.

Cloud secure-save, vault unlock and retrieval, encrypted multi-vault/TOTP
workflows, token revocation, two-account removal/key rotation, recovery and
native helper installation still require the consolidated session in
[FINAL_BROWSER_CHECK.md](FINAL_BROWSER_CHECK.md). These synthetic fixture cases
must never be cited as completion of those gates.
