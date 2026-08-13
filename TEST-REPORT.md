# SovereignRoot v0.1.1 — Test Report

Tested: **13 August 2026**

This report records checks performed against the packaged static reference implementation.

## Automated cryptographic / policy tests

Command:

```text
node tests/run-tests.mjs
```

Checks:

- deterministic canonicalization and rejection of unsupported numeric values;
- P-256 signing identity generation and JWK-thumbprint key identifier;
- document signing and verification;
- post-signing tamper detection;
- encrypted private-key bundle round trip and wrong-passphrase rejection;
- deny / approval precedence;
- finance approval threshold evaluation;
- blocked domain/subdomain evaluation;
- blocked recipient evaluation;
- downstream/root decision intersection.

Expected result: **All tests passed.**

## JSON Schema + independent verifier

`protocol/example.sovereignty.json` is checked against
`protocol/sovereignty.schema.json` using JSON Schema Draft 2020-12 and then
verified using the same public verifier exported for integrators.

Expected result: schema valid and signature valid.

## Static deployment audit

Command:

```text
python tests/static-audit.py
```

Checks include:

- local asset references exist;
- no remote executable dependencies;
- no `/functions` directory;
- CSP/security headers are present;
- application modules contain no fetch/XHR/WebSocket calls;
- JavaScript syntax checks;
- package remains far below Cloudflare static file-count and per-file limits;
- common accidental-secret patterns are absent;
- direct DOM ID references used by the app exist in the HTML;
- no duplicate element IDs;
- all seven wizard panels exist.

Expected result: **Static audit passed.**

## Local HTTP asset smoke test

Command:

```text
python tests/http-smoke.py
```

Checks that the entry point and critical static assets can be served over HTTP.

Expected result: **HTTP smoke passed.**

## Browser E2E limitation in build environment

A full automated Chromium interaction test was attempted during packaging, but
the managed build environment blocks navigation to both loopback HTTP origins
and `file://` URLs with an administrator policy. Consequently, a true browser
click-through E2E run could not be completed in this environment.

This is an environment limitation, not recorded as a browser-pass. The static,
cryptographic, schema and HTTP smoke suites above remain independently runnable
from the package.


## v0.1.1 direct-open regression

The package was corrected after a direct `file://` preview exposed root-relative asset paths and ES-module loading assumptions. The v0.1.1 regression audit verifies relative CSS/image/manifest/document links, a dependency-free classic browser bundle, absence of root-relative local asset URLs, and absence of ES-module imports/exports in the production bundle.

Run: `python tests/direct-open-audit.py`

A full visual browser run remains environment-dependent; Cloudflare Pages over HTTPS is the recommended production execution mode.
