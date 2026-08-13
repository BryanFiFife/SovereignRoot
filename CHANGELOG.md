# Changelog

## 0.1.1 — Direct-open compatibility
- Replaced root-relative browser asset paths with relative paths.
- Added a dependency-free classic browser bundle so `index.html` works from `file://` without ES-module CORS failures.
- Disabled service-worker registration when opened from disk.
- Added clipboard fallback for local-file mode.
- Kept the same static package deployable unchanged to Cloudflare Pages.

## 0.1.0 — 2026-08-13

- Initial SovereignRoot working specification.
- Static Cloudflare Pages-ready generator.
- Local ECDSA P-256 signing and verification.
- Encrypted private-key bundle export.
- Root deny-overrides and attenuation-only semantics.
- Policy continuity chain support.
- Generic reference evaluator and tests.
