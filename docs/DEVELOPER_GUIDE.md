# Developer integration guide

## Goal

Enforcement must occur on the action path, not merely in the prompt/context path.

```text
agent proposes action
        |
        v
normalize native call
        |
        v
verify active sovereignty.json
        |
        v
SovereignRoot evaluate
        |
        v
intersect downstream authorization
        |
    +---+---+
    |       |
   DENY    HOLD ----> trusted human approval
    |       |
    x      allow
            |
            v
        tool/service
```

## Boot behavior

For a security-sensitive integration:

- load the configured policy from a trusted location;
- verify its signature before enabling protected tool execution;
- refuse unsupported major/minor versions;
- cache the verified canonical payload hash alongside the parsed policy;
- re-verify after file changes;
- fail closed if verification fails.

## Action normalization

The most important adapter responsibility is mapping native operations into stable policy operations. Avoid using unstructured natural language as the sole authorization object.

Example:

```js
const action = {
  category: 'communications',
  operation: 'send_external',
  recipient: 'person@example.com',
  channel: 'email'
};
```

## Decision intersection

SovereignRoot never grants service authority. If the root says `allow` but OAuth/OS/service policy denies, the effective result remains deny.

If the root says `require_approval` but a task token says allow, the effective result is hold.

If the root says deny, effective result is always deny.

## TOCTOU

The exact operation that is evaluated must be the operation that executes. Avoid evaluating a summary and then allowing the agent to mutate arguments before forwarding.

For sensitive adapters, hash or freeze normalized arguments after evaluation and verify they have not changed before execution.
