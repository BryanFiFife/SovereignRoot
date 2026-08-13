# SovereignRoot interoperability notes

SovereignRoot is a **constraint ceiling**, not a grant system.

## Authority composition

Use this mental model:

```text
human root constraints (SovereignRoot)
             ∩
operator / task authorization
             ∩
agent identity / delegated credential scopes
             ∩
service / OS / application permissions
             =
       effective authority
```

Any layer may reduce authority. No lower layer may increase it beyond a higher-layer ceiling.

## OAuth / delegated tokens

OAuth or equivalent service credentials answer whether a token is permitted to invoke a service operation. A SovereignRoot-aware policy enforcement point should evaluate the proposed operation *before* presenting or using the delegated token.

## Agent identity protocols

Agent identity establishes who/what is acting and for whom. SovereignRoot establishes the human holder's persistent upper bound. Bind enforcement logs to both the agent identity and the active SovereignRoot payload hash where possible.

## Per-task receipts / operation authorization

Per-task authorization can be more specific than SovereignRoot. It may further narrow the allowed operation, amount, recipient or time window. If a task receipt permits something the root denies, root denial wins.

## MCP / tool calls

An MCP-style enforcement adapter can normalize each tool invocation to:

```json
{
  "category": "system",
  "operation": "execute_shell",
  "tool": "shell",
  "arguments_hash": "..."
}
```

Evaluate the normalized action before forwarding the call to the tool server.

## Hosted chat products

If a hosted product provides no pre-action policy hook, the file can still be supplied as an instruction, but this is advisory only. Do not market prompt-only use as cryptographic enforcement.
