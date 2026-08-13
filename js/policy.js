export const PROTOCOL_VERSION = '0.1.0';

export const PRESETS = {
  balanced: {
    unknown: 'require_approval', destructive: 'require_approval', externalComms: 'require_approval',
    publicPosting: 'require_approval', softwareInstall: 'require_approval', shell: 'require_approval', physical: 'require_approval',
    childAgents: false, childDepth: 0, secretExfiltration: 'deny', secretPersistence: 'deny', policyMutation: 'deny',
    singleSpend: '10000', dailySpend: '25000', currency: 'GBP', newPayee: 'require_approval'
  },
  strict: {
    unknown: 'deny', destructive: 'deny', externalComms: 'require_approval', publicPosting: 'deny', softwareInstall: 'deny',
    shell: 'require_approval', physical: 'deny', childAgents: false, childDepth: 0, secretExfiltration: 'deny',
    secretPersistence: 'deny', policyMutation: 'deny', singleSpend: '5000', dailySpend: '10000', currency: 'GBP', newPayee: 'deny'
  },
  developer: {
    unknown: 'require_approval', destructive: 'require_approval', externalComms: 'require_approval', publicPosting: 'require_approval',
    softwareInstall: 'allow', shell: 'allow', physical: 'require_approval', childAgents: true, childDepth: 2,
    secretExfiltration: 'deny', secretPersistence: 'deny', policyMutation: 'deny', singleSpend: '10000', dailySpend: '25000',
    currency: 'GBP', newPayee: 'require_approval'
  },
  lockdown: {
    unknown: 'deny', destructive: 'deny', externalComms: 'deny', publicPosting: 'deny', softwareInstall: 'deny', shell: 'deny',
    physical: 'deny', childAgents: false, childDepth: 0, secretExfiltration: 'deny', secretPersistence: 'deny',
    policyMutation: 'deny', singleSpend: '0', dailySpend: '0', currency: 'GBP', newPayee: 'deny'
  }
};

function rule(id, category, operation, effect, description, conditions = undefined) {
  const r = { id, category, operation, effect, description };
  if (conditions && Object.keys(conditions).length) r.conditions = conditions;
  return r;
}

function listFromText(value) {
  return (value || '').split(/\n|,/).map(v => v.trim()).filter(Boolean);
}

export function buildSovereigntyPayload(form, publicKey, keyId, previousHash = null) {
  const now = new Date().toISOString();
  const rules = [
    rule('root.policy.modify', 'governance', 'modify_root_policy', 'deny', 'An agent may never alter, weaken, replace, disable, or bypass this root policy.'),
    rule('root.enforcement.disable', 'governance', 'disable_enforcement', 'deny', 'An agent may never disable or evade a compliant SovereignRoot enforcement point.'),
    rule('root.signing-key.access', 'governance', 'access_signing_key', 'deny', 'An agent may never request, reveal, export, transmit, or use the holder private signing key.'),
    rule('identity.impersonate', 'identity', 'impersonate_holder', form.impersonation || 'deny', 'Do not impersonate the holder or claim the holder personally performed an AI-generated action.'),
    rule('identity.legal-acceptance', 'identity', 'accept_legal_terms', form.legalAcceptance || 'require_approval', 'Legal terms, contracts, declarations, or attestations require the configured human decision.'),
    rule('secrets.exfiltrate', 'secrets', 'transmit_secret', form.secretExfiltration || 'deny', 'Credentials, recovery phrases, private keys, tokens and passwords must not be disclosed or transmitted.'),
    rule('secrets.persist', 'secrets', 'persist_secret', form.secretPersistence || 'deny', 'Secrets must not be written into long-term memory, logs, prompts, notes, or ordinary files.'),
    rule('data.delete', 'data', 'delete_data', form.destructive || 'require_approval', 'Deletion of user data follows the configured destructive-action policy.'),
    rule('data.bulk-export', 'data', 'bulk_export', form.bulkExport || 'require_approval', 'Bulk export of personal or private data requires the configured decision.'),
    rule('communication.external-send', 'communications', 'send_external', form.externalComms || 'require_approval', 'Sending messages to external recipients follows the configured communication policy.'),
    rule('communication.public-publish', 'communications', 'publish_public', form.publicPosting || 'require_approval', 'Public posting, commenting, publishing, or broadcasting follows the configured policy.'),
    rule('system.install', 'system', 'install_software', form.softwareInstall || 'require_approval', 'Installing software, extensions, packages, services, or persistent components follows the configured policy.'),
    rule('system.shell', 'system', 'execute_shell', form.shell || 'require_approval', 'Shell, terminal, PowerShell, or equivalent command execution follows the configured policy.'),
    rule('system.security-controls', 'system', 'modify_security_controls', 'deny', 'Do not weaken firewalls, EDR, antivirus, access control, sandboxing, audit, or other security controls.'),
    rule('physical.control', 'physical', 'control_physical_device', form.physical || 'require_approval', 'Actions affecting physical devices, vehicles, locks, machinery, cameras or microphones follow the configured policy.'),
    rule('agents.spawn', 'delegation', 'spawn_child_agent', form.childAgents ? 'allow' : 'deny', 'Child-agent creation follows the holder policy.', { max_depth: Number(form.childDepth || 0), must_attenuate: true }),
    rule('agents.authority-amplification', 'delegation', 'amplify_authority', 'deny', 'No child, delegated agent, tool, model, or derived context may obtain authority exceeding its parent or this root.'),
    rule('finance.new-payee', 'finance', 'pay_new_recipient', form.newPayee || 'require_approval', 'Payments to a new or previously unapproved recipient follow the configured policy.'),
  ];

  const currency = (form.currency || 'GBP').toUpperCase();
  const singleSpend = String(form.singleSpend ?? '0').replace(/[^0-9]/g, '') || '0';
  const dailySpend = String(form.dailySpend ?? '0').replace(/[^0-9]/g, '') || '0';

  rules.push(rule('finance.single-limit', 'finance', 'transfer_value', 'require_approval', 'Transactions above the holder-defined single-transaction ceiling require explicit approval.', {
    currency,
    amount_minor_gt: singleSpend
  }));
  rules.push(rule('finance.daily-limit', 'finance', 'transfer_value', 'require_approval', 'Aggregate daily spending above the holder-defined ceiling requires explicit approval.', {
    currency,
    aggregate_24h_minor_gt: dailySpend
  }));

  const blockedRecipients = listFromText(form.blockedRecipients);
  if (blockedRecipients.length) {
    rules.push(rule('communication.blocked-recipients', 'communications', 'contact_recipient', 'deny', 'Do not contact listed recipients.', { recipients: blockedRecipients }));
  }
  const blockedDomains = listFromText(form.blockedDomains).map(x => x.toLowerCase());
  if (blockedDomains.length) {
    rules.push(rule('network.blocked-domains', 'network', 'connect_domain', 'deny', 'Do not connect to listed domains.', { domains: blockedDomains }));
  }

  const payload = {
    protocol: 'SovereignRoot',
    version: PROTOCOL_VERSION,
    document_type: 'sovereignty-root',
    created_at: now,
    subject: {
      id: keyId,
      display_name: (form.displayName || '').trim() || undefined
    },
    semantics: {
      model: 'deny-overrides',
      unknown_action: form.unknown || 'require_approval',
      non_derogation: true,
      default_inheritance: 'attenuation-only',
      effective_authority: 'delegated_authority INTERSECT root_allowed_authority',
      note: 'A grant from any downstream authorization system cannot override a SovereignRoot deny.'
    },
    lifecycle: {
      previous_payload_sha256: previousHash || null,
      replacement_requires_holder_signature: true,
      agent_self_amendment: false
    },
    rules,
    public_key: publicKey
  };
  if (!payload.subject.display_name) delete payload.subject.display_name;
  return payload;
}

export function summarizePolicy(document) {
  const rules = Array.isArray(document?.rules) ? document.rules : [];
  return {
    total: rules.length,
    deny: rules.filter(r => r.effect === 'deny').length,
    approval: rules.filter(r => r.effect === 'require_approval').length,
    allow: rules.filter(r => r.effect === 'allow').length,
    unknown: document?.semantics?.unknown_action || 'unknown',
    childAgents: rules.find(r => r.id === 'agents.spawn')?.effect || 'unknown',
    currency: rules.find(r => r.id === 'finance.single-limit')?.conditions?.currency || '—',
    singleSpendMinor: rules.find(r => r.id === 'finance.single-limit')?.conditions?.amount_minor_gt || '—',
    dailySpendMinor: rules.find(r => r.id === 'finance.daily-limit')?.conditions?.aggregate_24h_minor_gt || '—'
  };
}

export function installGuide(document) {
  const kid = document.proof?.key_id || document.subject?.id || '(key id)';
  return `# Install your SovereignRoot policy\n\nYour file: sovereignty.json\nKey ID: ${kid}\n\n## Important\n\nsovereignty.json is a signed policy artifact, not magic. It only becomes a security control when an agent runtime, tool proxy, operating-system boundary, or other trusted enforcement point verifies and enforces it BEFORE actions execute. Do not rely on the language model to police itself.\n\n## Recommended location\n\nCreate a read-only directory outside your agent workspace:\n\n- Windows: %USERPROFILE%\\.sovereignroot\\sovereignty.json\n- macOS/Linux: ~/.sovereignroot/sovereignty.json\n\nKeep your encrypted sovereignroot-key.json OFFLINE and separate. Never place it in an agent-readable workspace, cloud sync folder, prompt, memory store, repo, or secrets manager accessible by the agent.\n\n## Runtime contract\n\nA conforming enforcement point should:\n\n1. Load sovereignty.json from a trusted path.\n2. Verify its RFC 8785 canonical payload and ECDSA P-256 signature.\n3. Reject unsigned, malformed, unsupported, or tampered policies.\n4. Normalize every proposed action to a category + operation + structured attributes.\n5. Apply deny-overrides semantics. A root deny always beats any downstream grant.\n6. Apply numeric/list constraints such as spend limits and blocked recipients.\n7. Treat require_approval as a hard HOLD until fresh human approval is obtained through a channel the agent cannot forge.\n8. Never allow a child agent or delegated credential to exceed parent authority.\n9. Fail closed for security-sensitive actions if the policy cannot be verified.\n10. Log the policy payload hash with each enforcement decision.\n\n## Advisory-only use\n\nIf your current agent has no hard enforcement integration, you may point it at the file as an additional instruction source, but this is advisory only and MUST NOT be represented as equivalent to runtime enforcement.\n\n## Developer integration\n\nSee protocol/SOVEREIGNROOT-SPEC.md and reference/ for the schema, verifier and policy-engine reference code.\n`;
}
