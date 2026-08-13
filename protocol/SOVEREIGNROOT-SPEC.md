# SovereignRoot Working Specification v0.1.0

**Status:** Working Draft  
**Document type:** Human-owned root constraint policy for autonomous AI systems  
**Default filename:** `sovereignty.json`

## 1. Purpose

SovereignRoot defines a portable, cryptographically signed **upper bound on delegated AI authority**. It does not grant authority and it does not replace authentication or task authorization. It defines actions that remain denied or require fresh human approval even when another system has granted an agent broader permissions.

A conforming implementation MUST apply this invariant:

> **Effective authority = delegated authority ∩ SovereignRoot allowed authority.**

When multiple applicable rules conflict, effect precedence is:

> **DENY > REQUIRE_APPROVAL > ALLOW**

A downstream grant MUST NOT override a SovereignRoot deny.

## 2. Why this is a separate layer

Existing and emerging agent authorization systems focus primarily on identity, delegation, scopes, per-task authorization, audit receipts or service-to-agent trust. SovereignRoot is intentionally narrower: it is a **persistent human-owned root constraint document** that can be referenced by those systems as a non-derogable ceiling.

The root is expected to outlive individual:

- models;
- agent frameworks;
- vendors;
- task grants;
- OAuth tokens;
- prompts and conversations;
- child-agent trees.

## 3. Non-goals

SovereignRoot does **not**:

- make prompt injection impossible;
- create a security boundary merely by being placed in a model prompt;
- replace OS permissions, sandboxing, OAuth, mTLS, WebAuthn or agent identity;
- guarantee that a malicious or non-conforming runtime will obey it;
- store passwords, private keys, API tokens, seed phrases or recovery codes;
- claim to be an IETF, W3C or NIST standard.

## 4. Trust model

The trusted computing base is intentionally small:

1. the holder's private signing key;
2. a verifier that correctly validates the signed root;
3. an enforcement point that executes **before** the protected action;
4. any human-approval channel used for `require_approval` decisions.

The language model itself SHOULD NOT be treated as the enforcement point.

## 5. Document structure

A v0.1 document contains:

- `protocol`: literal `SovereignRoot`;
- `version`: protocol version;
- `document_type`: literal `sovereignty-root`;
- `created_at`: RFC 3339 / ISO 8601 timestamp;
- `subject`: holder signing identity and optional display alias;
- `semantics`: deny-overrides and attenuation rules;
- `lifecycle`: continuity metadata;
- `rules`: machine-readable constraints;
- `public_key`: P-256 public JWK;
- `proof`: canonical-payload digest and signature.

The normative JSON shape for this working draft is in `sovereignty.schema.json`.

## 6. Cryptographic profile

### 6.1 Canonicalization

Before hashing or signing, implementations MUST remove the top-level `proof` member and canonicalize the remaining JSON using **RFC 8785 JSON Canonicalization Scheme (JCS)**.

Implementations MUST reject inputs that cannot be represented safely under the profile. The reference implementation also rejects negative zero in line with verified RFC 8785 errata guidance.

### 6.2 Digest

The canonical UTF-8 payload is hashed with SHA-256. The digest is base64url encoded without padding and placed at `proof.payload_sha256`.

### 6.3 Signing key

The v0.1 mandatory signing profile is ECDSA using NIST P-256 and SHA-256. The public key is embedded as a JWK.

### 6.4 Key identity

The holder identity is derived from an RFC 7638 SHA-256 JWK Thumbprint of the required EC public-key members (`crv`, `kty`, `x`, `y`) and represented using the RFC 9278 JWK Thumbprint URI form:

`urn:ietf:params:oauth:jwk-thumbprint:sha-256:<base64url-thumbprint>`

The value MUST equal both `subject.id` and `proof.key_id`.

### 6.5 Signature

The signature input is the exact UTF-8 bytes of the RFC 8785 canonical payload. The signature is encoded using base64url without padding.

## 7. Policy semantics

### 7.1 Effects

Each rule has one of three effects:

- `deny`: action MUST NOT execute;
- `require_approval`: action MUST be held until fresh human approval is obtained through a trusted channel;
- `allow`: the root does not prohibit the action, subject to all other applicable policy and authorization layers.

### 7.2 Unknown actions

`semantics.unknown_action` defines the decision when no root rule matches. Security-sensitive deployments SHOULD use `deny` or `require_approval`.

### 7.3 Non-derogation

`semantics.non_derogation` is always `true` in v0.1. A downstream policy, OAuth grant, agent credential, child-agent grant, system prompt, retrieved memory or operator instruction MUST NOT weaken a root deny.

### 7.4 Delegation attenuation

Child/sub-agents MAY be allowed by policy, but their effective authority MUST be a subset of both their parent authority and the active root. A delegation that amplifies authority MUST be denied.

## 8. Protected root invariants

The public generator always emits these hard-deny rules:

1. `root.policy.modify` — agents may not alter, replace, weaken, disable or bypass the root policy;
2. `root.enforcement.disable` — agents may not disable or evade a compliant enforcement point;
3. `root.signing-key.access` — agents may not access or use the holder private signing key;
4. `system.security-controls` — agents may not weaken security controls;
5. `agents.authority-amplification` — delegated authority cannot exceed the parent/root ceiling.

A future protocol revision may introduce explicit profiles, but a v0.1 implementation MUST NOT silently remove these invariants while still claiming generator conformance.

## 9. Lifecycle and replacement

A root may be replaced by the human holder. This is not considered agent self-amendment.

A replacement SHOULD:

- use the same holder signing identity;
- set `lifecycle.previous_payload_sha256` to the verified payload digest of the predecessor;
- be distributed atomically to enforcement points;
- cause previous active roots to be retained for audit but marked superseded.

A runtime MUST NOT accept a purported replacement merely because an agent says it is newer. It MUST verify the replacement signature and local trust configuration.

## 10. Enforcement algorithm

A conforming pre-action enforcement point SHOULD perform these steps:

1. Load the root from a trusted path or trusted configuration source.
2. Validate required structure and supported protocol version.
3. Recompute holder key identity from the embedded public key.
4. Canonicalize the unsigned payload.
5. Recompute SHA-256 payload digest.
6. Verify the ECDSA signature.
7. Normalize the proposed action to a structured action object.
8. Find all applicable root rules.
9. Apply condition predicates.
10. Resolve conflicts using `deny > require_approval > allow`.
11. If no rule applies, use `semantics.unknown_action`.
12. Intersect the result with downstream authorization.
13. For `require_approval`, HOLD until trusted fresh approval is obtained.
14. For `deny`, prevent execution.
15. Log the root payload digest and decision.

A security-sensitive implementation SHOULD fail closed if signature verification, parsing or policy evaluation fails.

## 11. Normalized action model

SovereignRoot intentionally does not mandate a transport. Enforcement adapters map native actions into a small structured object, for example:

```json
{
  "category": "finance",
  "operation": "transfer_value",
  "amount_minor": "12500",
  "currency": "GBP",
  "recipient": "merchant-123",
  "aggregate_24h_minor": "17000"
}
```

or:

```json
{
  "category": "communications",
  "operation": "publish_public",
  "channel": "social"
}
```

Amounts SHOULD be represented as integer strings in minor currency units.

## 12. Privacy guidance

A `sovereignty.json` is usually safe to share with enforcement systems because it contains only a public signing key, but the policy itself can contain sensitive preferences, contact identifiers or domain lists. Users SHOULD treat it as private configuration unless they intentionally publish it.

A SovereignRoot document MUST NOT contain holder private signing keys, passwords, authentication cookies, access tokens, recovery phrases or other secrets.

## 13. Key custody

The reference website encrypts the exported private signing JWK locally using PBKDF2-HMAC-SHA256 and AES-256-GCM before download.

Recommended operational practice:

- keep at least two offline copies of the encrypted key bundle;
- store the passphrase separately;
- do not place the private key bundle in an AI-readable workspace;
- do not upload it to an agent, chat, model memory, source repository or generic cloud storage that the agent can access;
- rotate to a new root identity if key compromise is suspected.

## 14. Interoperability

SovereignRoot is designed to sit above task/delegation authorization systems.

Examples:

- OAuth says an agent **can** send mail; SovereignRoot says public/external sends require approval → **HOLD**.
- An agent delegation receipt allows a £500 transfer; SovereignRoot has a £100 per-transaction approval ceiling → **HOLD**.
- A child-agent token grants package installation; SovereignRoot denies software installation → **DENY**.
- A downstream service denies an action SovereignRoot allows → **DENY**, because SovereignRoot is a ceiling, not a grant.

See `INTEROP.md` for mapping guidance.

## 15. Versioning

This document defines Working Draft `0.1.x`. Implementations MUST NOT assume future major/minor versions preserve identical semantics.

The protocol should eventually standardize:

- a capability/action registry;
- explicit policy-diff semantics for detecting weakening vs tightening;
- multi-key and hardware-backed replacement ceremonies;
- revocation/recovery profiles;
- test vectors;
- bindings for major agent/tool protocols;
- a formal conformance suite.

## 16. Security warning

SovereignRoot is valuable only when enforced at a boundary the agent cannot simply bypass. An implementation that merely prepends the JSON to an LLM prompt is **advisory**, not conforming hard enforcement.
