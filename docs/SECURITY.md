# SovereignRoot security model

## The central promise

SovereignRoot makes a human policy **tamper-evident and portable**. It does not make a non-conforming agent obey it.

Hard enforcement exists only when a trusted component that the agent cannot bypass verifies and evaluates the active root **before execution**.

## Threats addressed

A correct integration can help contain:

- over-broad delegated credentials;
- accidental or malicious authority amplification in child agents;
- prompts or retrieved memories that instruct an agent to exceed human limits;
- an agent attempting to weaken its own governance layer;
- unauthorized public communication, destructive operations, spending or system changes that match configured rules;
- silent modification of `sovereignty.json`.

## Threats not solved by the file alone

- compromise of the host or trusted enforcement component;
- theft of the holder private signing key;
- a tool path that bypasses enforcement;
- incorrect action normalization;
- malicious enforcement software that ignores the policy;
- social engineering of the human approval channel;
- model outputs that cause harm without invoking an enforceable action;
- physical-world effects not represented to the policy engine.

## Private signing key

The signing key is more sensitive than `sovereignty.json`. The public file is designed to be presented to runtimes; the private key is not.

The browser reference generator:

1. creates an ECDSA P-256 key pair with Web Crypto;
2. exports the private JWK only in browser memory;
3. derives a local AES-256-GCM encryption key from the user's passphrase with PBKDF2-HMAC-SHA256;
4. encrypts the private JWK;
5. downloads the encrypted bundle;
6. never sends it to a server.

Keep the encrypted key bundle outside any location the agent can read.

## Website supply-chain consideration

Because a website can theoretically be changed by its host, high-assurance users should:

- self-host a reviewed release;
- pin/review release hashes;
- use the included Content Security Policy;
- disconnect the network after loading a reviewed copy if desired;
- verify generated policy signatures independently with the reference verifier.

No remote JavaScript, font, analytics or API dependency is used in the supplied build.

## Approval channels

`require_approval` is only meaningful if approval is collected through a channel the agent cannot forge or silently self-satisfy. For high-impact operations, use an independent trusted UI, OS prompt, hardware token, or other out-of-band mechanism.
