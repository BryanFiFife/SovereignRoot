# SovereignRoot

**Your rules above the AI.**

SovereignRoot is a static, local-first website and working protocol specification for generating a cryptographically signed `sovereignty.json`: a human-owned root constraint policy for autonomous AI systems.

## Local preview

You may now double-click `index.html` directly. Version 0.1.1 uses only relative asset paths and a dependency-free browser bundle, so styling and application logic load under `file://` as well as HTTPS. Cloudflare Pages remains the recommended public deployment because it provides normal HTTPS origin semantics and security headers.


## What ships in this package

- production-ready static website;
- guided policy generator;
- four sensible presets;
- local ECDSA P-256 key generation;
- encrypted private-key export using PBKDF2 + AES-256-GCM;
- RFC 8785 canonical JSON signing;
- RFC 7638 / RFC 9278-style public signing identity;
- local drag-and-drop signature verifier;
- policy continuity support for signed replacements;
- deny-overrides / attenuation-only policy semantics;
- JSON Schema;
- working specification;
- generic reference verifier and policy engine;
- user, developer, security and Cloudflare deployment guides;
- strict static security headers;
- no external JavaScript, fonts, analytics, APIs, backend or database;
- test suite.

## Zero-cost hosting design

The site is ordinary static HTML/CSS/JavaScript. It deliberately contains no `/functions` directory and requires no Cloudflare Worker.

Deploy the directory containing `index.html` directly to Cloudflare Pages. See `docs/DEPLOY_CLOUDFLARE.md`.

## Local development

From this directory:

```bash
python -m http.server 8080
```

Then open:

```text
http://127.0.0.1:8080
```

Use HTTP only on localhost. Public deployment should use HTTPS so Web Crypto is available in a secure context.

## Tests

Requires Node.js 22+ for the included no-dependency test runner:

```bash
node tests/run-tests.mjs
```

## Core invariant

```text
Effective authority = delegated authority ∩ SovereignRoot allowed authority
```

Decision precedence:

```text
DENY > REQUIRE_APPROVAL > ALLOW
```

SovereignRoot is a ceiling, not a grant. A lower layer may always reduce authority further.

## Security honesty

A signed `sovereignty.json` is tamper-evident and portable, but it does not force arbitrary AI products to obey it. Hard enforcement requires a trusted pre-action enforcement point that verifies and evaluates the root before execution.

Prompt-only use is advisory.

## Never put secrets in sovereignty.json

Do not include:

- passwords;
- API keys;
- authentication tokens;
- seed/recovery phrases;
- private cryptographic keys;
- session cookies.

The generator is designed around policy rules, not secret storage.

## Project structure

```text
/
├── index.html
├── css/styles.css
├── js/
│   ├── app.js
│   ├── crypto.js
│   └── policy.js
├── assets/
├── protocol/
│   ├── SOVEREIGNROOT-SPEC.md
│   ├── sovereignty.schema.json
│   ├── example.sovereignty.json
│   └── INTEROP.md
├── reference/
│   ├── verifier.mjs
│   ├── policy-engine.mjs
│   └── README.md
├── docs/
│   ├── SECURITY.md
│   ├── USER_GUIDE.md
│   ├── DEVELOPER_GUIDE.md
│   ├── DEPLOY_CLOUDFLARE.md
│   ├── MARKETING.md
│   └── RESEARCH.md
├── tests/
│   ├── run-tests.mjs
│   ├── static-audit.py
│   └── http-smoke.py
├── TEST-REPORT.md
├── LAUNCH-CHECKLIST.md
├── _headers
├── _redirects
├── manifest.webmanifest
├── sw.js
├── robots.txt
└── sitemap.xml
```


## Verification

Run the packaged checks locally:

```text
node tests/run-tests.mjs
python tests/static-audit.py
python tests/http-smoke.py
```

See `TEST-REPORT.md` for scope and the recorded browser-E2E environment limitation.

## Brand/status

**SovereignRoot** is the working product/format brand for this package. The earlier concept label “Human Sovereignty Protocol” is intentionally not used as the main brand because that exact phrase has existing public prior use.

The protocol format is a **Working Draft v0.1.0**, not an official IETF, W3C or NIST standard.

## Before public launch

1. Confirm the final Cloudflare Pages project/domain name.
2. Replace `sovereignroot.pages.dev` in `robots.txt`, `sitemap.xml`, and the JSON Schema `$id` if the hostname differs.
3. Put the source in a public Git repository if you want maximum trust and protocol adoption.
4. Publish test vectors and signed releases.
5. Add runtime adapters only when they can enforce pre-action, not merely inject prompt instructions.

## License

Apache License 2.0. See `LICENSE`.
