# Research and differentiation notes

Research snapshot: **13 August 2026**.

This document records the landscape reviewed before defining SovereignRoot v0.1. It is not a claim that no related work exists.

## Standards environment

### NIST AI Agent Standards Initiative

NIST launched the AI Agent Standards Initiative in February 2026 around interoperable agent standards, community-led protocols, and research into agent security, authentication and identity.

- https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative

### AI Agent Authentication and Authorization

An active June 2026 IETF Internet-Draft describes how existing identity/auth standards such as OAuth and WIMSE can be applied to AI agents rather than inventing a wholly new authorization protocol.

- https://datatracker.ietf.org/doc/html/draft-klrc-aiagent-auth-02

### Agent Identity Protocol proposals

Multiple drafts address verifiable agent identity, policy enforcement, delegation and scope attenuation.

- https://datatracker.ietf.org/doc/html/draft-aip-agent-identity-protocol-00
- https://datatracker.ietf.org/doc/draft-singla-agent-identity-protocol/01/

### Delegated Agent Authorization Protocol (DAAP)

DAAP work includes persistent agent identity, multi-agent delegation, scope attenuation and tamper-evident audit concepts.

- https://datatracker.ietf.org/doc/draft-mishra-oauth-agent-grants/

### Agent Operation Authorization

This draft addresses verifiable human delegation of specific operations to AI agents.

- https://datatracker.ietf.org/doc/html/draft-liu-agent-operation-authorization-01

### Delegation Receipt Protocol (DRP)

DRP is especially relevant prior art. Its May 2026 draft uses user-signed per-delegation authorization objects containing scope, boundaries and time windows, and states that boundaries cannot be waived by an operator.

- https://datatracker.ietf.org/doc/html/draft-nelson-agent-delegation-receipts-09

## SovereignRoot's deliberately narrower position

SovereignRoot should **not** claim to have invented human-signed boundaries or non-waivable AI authorization constraints.

Its intended differentiation is the productization and standardization of a **persistent, task-independent, human-owned root constraint document** designed to remain above:

- individual task receipts;
- agent identities;
- OAuth grants;
- model/provider changes;
- prompts and memories;
- child-agent delegation chains.

It is a reusable **ceiling** rather than a per-task authorization artifact.

## Naming research

The exact phrase “Human Sovereignty Protocol” had prior public use before this project, including a 2025 article by Greg Twemlow and a 2026 book subtitle. Therefore this package uses **SovereignRoot** as its working product/format brand.

Brand/domain/trademark clearance is still a separate legal/business step and has not been represented as completed.

## Cryptographic foundations

SovereignRoot intentionally composes existing standards rather than inventing cryptography:

- RFC 8785 — JSON Canonicalization Scheme (JCS): https://www.rfc-editor.org/rfc/rfc8785.html
- RFC 7638 — JSON Web Key Thumbprint: https://www.rfc-editor.org/rfc/rfc7638.html
- RFC 9278 — JWK Thumbprint URI: https://www.rfc-editor.org/rfc/rfc9278.html
- W3C Web Cryptography API / Level 2 work: https://www.w3.org/TR/webcrypto-2/

## Hosting research

Cloudflare's current Pages documentation states that requests to static assets are free and unlimited, while Pages Functions consume Workers quotas. This package uses only static assets and no Functions.

- https://developers.cloudflare.com/pages/functions/pricing/
- https://developers.cloudflare.com/pages/functions/routing/
