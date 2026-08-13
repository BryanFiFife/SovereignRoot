# SovereignRoot reference code

This directory contains deliberately small reference components.

- `verifier.mjs` re-exports the cryptographic verifier used by the website.
- `policy-engine.mjs` demonstrates deterministic deny-overrides evaluation after an implementation has normalized a native action.

## Important integration order

1. Verify `sovereignty.json` cryptographically.
2. Normalize the proposed native tool/API/device action.
3. Evaluate the root with `evaluateRoot()`.
4. Intersect the root decision with all downstream authorization decisions.
5. Execute only if the effective result is `allow`.
6. For `require_approval`, stop and obtain fresh trusted human approval.
7. For `deny`, stop.

The reference engine is intentionally narrow. Production adapters must define precise action normalization for their tool ecosystem and must not treat unrecognized native actions as a matched allow.
