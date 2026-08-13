/* SovereignRoot v0.1.1 browser bundle — generated from source modules. */
(()=>{
'use strict';
const te = new TextEncoder();
const td = new TextDecoder();

function bytesToBase64Url(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function assertValidString(value) {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xD800 && c <= 0xDBFF) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xDC00 && next <= 0xDFFF)) throw new TypeError('Lone high surrogate is not valid JCS input.');
      i++;
    } else if (c >= 0xDC00 && c <= 0xDFFF) {
      throw new TypeError('Lone low surrogate is not valid JCS input.');
    }
  }
}

function canonicalizeInner(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') {
    assertValidString(value);
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('NaN and Infinity are not valid JCS input.');
    if (Object.is(value, -0)) throw new TypeError('Negative zero is rejected per RFC 8785 errata guidance.');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return '[' + value.map(canonicalizeInner).join(',') + ']';
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map(key => {
      assertValidString(key);
      if (value[key] === undefined) throw new TypeError(`Undefined is not valid JCS input at key ${key}.`);
      return JSON.stringify(key) + ':' + canonicalizeInner(value[key]);
    }).join(',') + '}';
  }
  throw new TypeError(`Unsupported JCS input type: ${typeof value}`);
}

function canonicalize(value) {
  return canonicalizeInner(value);
}

async function sha256Bytes(data) {
  const bytes = typeof data === 'string' ? te.encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

async function sha256Base64Url(data) {
  return bytesToBase64Url(await sha256Bytes(data));
}

async function sha256Hex(data) {
  return [...await sha256Bytes(data)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function generateSigningKeyPair() {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
}

async function exportPublicJwk(publicKey) {
  const jwk = await crypto.subtle.exportKey('jwk', publicKey);
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, alg: 'ES256', key_ops: ['verify'], ext: true };
}

async function exportPrivateJwk(privateKey) {
  return crypto.subtle.exportKey('jwk', privateKey);
}

async function importPublicJwk(jwk) {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
}

async function importPrivateJwk(jwk) {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign']
  );
}

async function jwkThumbprint(publicJwk) {
  const core = { crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y };
  return sha256Base64Url(canonicalize(core));
}

async function keyIdFromPublicJwk(publicJwk) {
  return `urn:ietf:params:oauth:jwk-thumbprint:sha-256:${await jwkThumbprint(publicJwk)}`;
}

function unsignedPayload(document) {
  const clone = structuredClone(document);
  delete clone.proof;
  return clone;
}

async function signDocument(document, privateKey, keyId) {
  const payload = unsignedPayload(document);
  const canonical = canonicalize(payload);
  const digest = await sha256Base64Url(canonical);
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    te.encode(canonical)
  ));
  document.proof = {
    type: 'SovereignRootProof',
    canonicalization: 'RFC8785-JCS',
    hash: 'SHA-256',
    signature_algorithm: 'ECDSA-P256-SHA256',
    key_id: keyId,
    payload_sha256: digest,
    signature: bytesToBase64Url(signature)
  };
  return document;
}

async function verifyDocument(document) {
  if (!document || typeof document !== 'object') return { valid: false, reason: 'Not a JSON object.' };
  if (!document.public_key || !document.proof) return { valid: false, reason: 'Missing public_key or proof.' };
  if (document.protocol !== 'SovereignRoot' || document.document_type !== 'sovereignty-root') return { valid: false, reason: 'Not a supported SovereignRoot document.' };
  if (!/^0\.1\.\d+$/.test(String(document.version || ''))) return { valid: false, reason: 'Unsupported SovereignRoot version.' };
  if (document.semantics?.model !== 'deny-overrides' || document.semantics?.non_derogation !== true) return { valid: false, reason: 'Unsupported or unsafe policy semantics.' };
  if (document.public_key.kty !== 'EC' || document.public_key.crv !== 'P-256' || document.public_key.alg !== 'ES256') return { valid: false, reason: 'Unsupported public-key profile.' };
  if (document.proof.type !== 'SovereignRootProof') return { valid: false, reason: 'Unsupported proof type.' };
  if (document.proof.canonicalization !== 'RFC8785-JCS') return { valid: false, reason: 'Unsupported canonicalization.' };
  if (document.proof.hash !== 'SHA-256') return { valid: false, reason: 'Unsupported proof hash.' };
  if (document.proof.signature_algorithm !== 'ECDSA-P256-SHA256') return { valid: false, reason: 'Unsupported signature algorithm.' };
  try {
    const keyId = await keyIdFromPublicJwk(document.public_key);
    if (keyId !== document.proof.key_id) return { valid: false, reason: 'Public key does not match proof key_id.' };
    if (document.subject?.id && document.subject.id !== keyId) return { valid: false, reason: 'Subject id does not match signing key.' };
    const payload = unsignedPayload(document);
    const canonical = canonicalize(payload);
    const digest = await sha256Base64Url(canonical);
    if (digest !== document.proof.payload_sha256) return { valid: false, reason: 'Payload hash mismatch.' };
    const publicKey = await importPublicJwk(document.public_key);
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      base64UrlToBytes(document.proof.signature),
      te.encode(canonical)
    );
    return ok
      ? { valid: true, reason: 'Signature and payload are valid.', keyId, digest }
      : { valid: false, reason: 'Signature verification failed.' };
  } catch (error) {
    return { valid: false, reason: error?.message || String(error) };
  }
}

async function encryptPrivateJwk(privateJwk, passphrase) {
  if (!passphrase || passphrase.length < 12) throw new Error('Use a passphrase of at least 12 characters.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const baseKey = await crypto.subtle.importKey('raw', te.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  const plaintext = te.encode(JSON.stringify(privateJwk));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext));
  return {
    format: 'sovereignroot-key-bundle',
    version: '1',
    warning: 'PRIVATE SIGNING KEY. KEEP OFFLINE. NEVER UPLOAD OR SHARE.',
    encryption: {
      cipher: 'AES-256-GCM',
      kdf: 'PBKDF2-HMAC-SHA256',
      iterations: 600000,
      salt: bytesToBase64Url(salt),
      iv: bytesToBase64Url(iv)
    },
    ciphertext: bytesToBase64Url(ciphertext)
  };
}

async function decryptPrivateJwk(bundle, passphrase) {
  if (bundle?.format !== 'sovereignroot-key-bundle') throw new Error('Not a SovereignRoot key bundle.');
  if (bundle?.encryption?.cipher !== 'AES-256-GCM' || bundle?.encryption?.kdf !== 'PBKDF2-HMAC-SHA256') {
    throw new Error('Unsupported key bundle encryption.');
  }
  const salt = base64UrlToBytes(bundle.encryption.salt);
  const iv = base64UrlToBytes(bundle.encryption.iv);
  const baseKey = await crypto.subtle.importKey('raw', te.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: bundle.encryption.iterations },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  try {
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, base64UrlToBytes(bundle.ciphertext));
    return JSON.parse(td.decode(plaintext));
  } catch {
    throw new Error('Unable to decrypt key bundle. Check the passphrase and file.');
  }
}

function downloadJson(filename, object) {
  const blob = new Blob([JSON.stringify(object, null, 2) + '\n'], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

function downloadText(filename, text, type = 'text/plain') {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

const PROTOCOL_VERSION = '0.1.0';

const PRESETS = {
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

function buildSovereigntyPayload(form, publicKey, keyId, previousHash = null) {
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

function summarizePolicy(document) {
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

function installGuide(document) {
  const kid = document.proof?.key_id || document.subject?.id || '(key id)';
  return `# Install your SovereignRoot policy\n\nYour file: sovereignty.json\nKey ID: ${kid}\n\n## Important\n\nsovereignty.json is a signed policy artifact, not magic. It only becomes a security control when an agent runtime, tool proxy, operating-system boundary, or other trusted enforcement point verifies and enforces it BEFORE actions execute. Do not rely on the language model to police itself.\n\n## Recommended location\n\nCreate a read-only directory outside your agent workspace:\n\n- Windows: %USERPROFILE%\\.sovereignroot\\sovereignty.json\n- macOS/Linux: ~/.sovereignroot/sovereignty.json\n\nKeep your encrypted sovereignroot-key.json OFFLINE and separate. Never place it in an agent-readable workspace, cloud sync folder, prompt, memory store, repo, or secrets manager accessible by the agent.\n\n## Runtime contract\n\nA conforming enforcement point should:\n\n1. Load sovereignty.json from a trusted path.\n2. Verify its RFC 8785 canonical payload and ECDSA P-256 signature.\n3. Reject unsigned, malformed, unsupported, or tampered policies.\n4. Normalize every proposed action to a category + operation + structured attributes.\n5. Apply deny-overrides semantics. A root deny always beats any downstream grant.\n6. Apply numeric/list constraints such as spend limits and blocked recipients.\n7. Treat require_approval as a hard HOLD until fresh human approval is obtained through a channel the agent cannot forge.\n8. Never allow a child agent or delegated credential to exceed parent authority.\n9. Fail closed for security-sensitive actions if the policy cannot be verified.\n10. Log the policy payload hash with each enforcement decision.\n\n## Advisory-only use\n\nIf your current agent has no hard enforcement integration, you may point it at the file as an additional instruction source, but this is advisory only and MUST NOT be represented as equivalent to runtime enforcement.\n\n## Developer integration\n\nSee protocol/SOVEREIGNROOT-SPEC.md and reference/ for the schema, verifier and policy-engine reference code.\n`;
}

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];


async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    try { await navigator.clipboard.writeText(text); return true; } catch {}
  }
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.style.position = 'fixed';
  area.style.opacity = '0';
  document.body.appendChild(area);
  area.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch {}
  area.remove();
  return ok;
}

const state = {
  step: 1,
  document: null,
  keyBundle: null,
  privateKey: null,
  publicJwk: null,
  previousHash: null,
  previousKeyId: null,
  _userInteracted: false
};

function toast(message, kind = 'info') {
  const el = $('#toast');
  el.textContent = message;
  el.dataset.kind = kind;
  el.classList.add('show');
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => el.classList.remove('show'), 3200);
}

function setStep(step) {
  state.step = Math.min(7, Math.max(1, step));
  $$('[data-step-panel]').forEach(panel => panel.hidden = Number(panel.dataset.stepPanel) !== state.step);
  $$('[data-step-indicator]').forEach(ind => {
    const n = Number(ind.dataset.stepIndicator);
    ind.classList.toggle('active', n === state.step);
    ind.classList.toggle('done', n < state.step);
  });
  // Only scroll to the generator on USER interaction, not on initial page load.
  if (state._userInteracted) {
    $('#generator')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

function setFormValue(name, value) {
  const els = $$(`[name="${name}"]`);
  if (!els.length) return;
  if (els[0].type === 'radio') {
    els.forEach(el => el.checked = String(el.value) === String(value));
  } else if (els[0].type === 'checkbox') {
    els[0].checked = Boolean(value);
  } else {
    els[0].value = value;
  }
}

function applyPreset(name) {
  const preset = PRESETS[name];
  if (!preset) return;
  Object.entries(preset).forEach(([key, value]) => setFormValue(key, value));
  $$('.preset').forEach(b => b.classList.toggle('selected', b.dataset.preset === name));
  $('#childDepth').disabled = !$('#childAgents').checked;
  toast(`${name[0].toUpperCase() + name.slice(1)} baseline applied.`);
}

function formObject() {
  const fd = new FormData($('#policyForm'));
  const obj = Object.fromEntries(fd.entries());
  obj.childAgents = fd.get('childAgents') === 'on';
  return obj;
}

function formatMoney(minor, currency) {
  if (minor === '—') return '—';
  const n = Number(minor || 0) / 100;
  try { return new Intl.NumberFormat(undefined, { style: 'currency', currency }).format(n); }
  catch { return `${currency} ${n.toFixed(2)}`; }
}

function renderResult(document) {
  const summary = summarizePolicy(document);
  $('#resultKeyId').textContent = document.proof.key_id;
  $('#resultHash').textContent = document.proof.payload_sha256;
  $('#resultRules').textContent = String(summary.total);
  $('#resultDenied').textContent = String(summary.deny);
  $('#resultApproval').textContent = String(summary.approval);
  $('#resultSpend').textContent = `${formatMoney(summary.singleSpendMinor, summary.currency)} / transaction`;
  $('#jsonPreview').textContent = JSON.stringify(document, null, 2);
  $('#resultStatus').textContent = 'Signed locally';
  $('#resultStatus').className = 'status-chip valid';
}

async function generatePolicy() {
  const button = $('#generateBtn');
  const passphrase = $('#keyPassphrase').value;
  const confirm = $('#keyPassphraseConfirm').value;
  if (passphrase.length < 12) return toast('Use a signing-key passphrase of at least 12 characters.', 'error');
  if (passphrase !== confirm) return toast('The two passphrases do not match.', 'error');
  if (!globalThis.crypto?.subtle) return toast('Web Crypto is unavailable. Use this site over HTTPS or localhost.', 'error');

  button.disabled = true;
  button.textContent = 'Generating & signing…';
  try {
    let privateKey = state.privateKey;
    let publicJwk = state.publicJwk;
    let privateJwk;

    if (!privateKey) {
      const pair = await generateSigningKeyPair();
      privateKey = pair.privateKey;
      publicJwk = await exportPublicJwk(pair.publicKey);
      privateJwk = await exportPrivateJwk(pair.privateKey);
    } else {
      privateJwk = await exportPrivateJwk(privateKey);
    }

    const keyId = await keyIdFromPublicJwk(publicJwk);
    if (state.previousKeyId && state.previousKeyId !== keyId) {
      throw new Error('The linked predecessor was signed by a different identity. Load its encrypted signing key before replacing it.');
    }
    const payload = buildSovereigntyPayload(formObject(), publicJwk, keyId, state.previousHash);
    const signed = await signDocument(payload, privateKey, keyId);
    const keyBundle = await encryptPrivateJwk(privateJwk, passphrase);

    state.document = signed;
    state.keyBundle = keyBundle;
    state.privateKey = privateKey;
    state.publicJwk = publicJwk;
    renderResult(signed);
    setStep(7);
    toast('Your sovereignty.json has been signed locally.', 'success');
  } catch (error) {
    console.error(error);
    toast(error?.message || 'Generation failed.', 'error');
  } finally {
    button.disabled = false;
    button.textContent = 'Generate & sign my sovereignty.json';
  }
}

async function importKeyBundle() {
  const file = $('#existingKeyFile').files[0];
  const pass = $('#existingKeyPassphrase').value;
  if (!file || !pass) return toast('Choose your encrypted key bundle and enter its passphrase.', 'error');
  try {
    const bundle = JSON.parse(await file.text());
    const privateJwk = await decryptPrivateJwk(bundle, pass);
    state.privateKey = await importPrivateJwk(privateJwk);
    state.publicJwk = { kty: privateJwk.kty, crv: privateJwk.crv, x: privateJwk.x, y: privateJwk.y, alg: 'ES256', key_ops: ['verify'], ext: true };
    const kid = await keyIdFromPublicJwk(state.publicJwk);
    $('#existingKeyStatus').textContent = `Loaded: ${kid}`;
    $('#existingKeyStatus').className = 'inline-status good';
    toast('Existing signing identity loaded. New files will keep the same identity.', 'success');
  } catch (error) {
    state.privateKey = null;
    state.publicJwk = null;
    $('#existingKeyStatus').textContent = error?.message || 'Unable to load key.';
    $('#existingKeyStatus').className = 'inline-status bad';
    toast(error?.message || 'Unable to load key.', 'error');
  }
}

async function importPreviousPolicy() {
  const file = $('#previousPolicyFile').files[0];
  if (!file) return;
  try {
    const document = JSON.parse(await file.text());
    const verification = await verifyDocument(document);
    if (!verification.valid) throw new Error(`Previous policy invalid: ${verification.reason}`);
    if (state.publicJwk) {
      const currentKid = await keyIdFromPublicJwk(state.publicJwk);
      if (currentKid !== verification.keyId) throw new Error('Previous policy belongs to a different signing identity.');
    }
    state.previousHash = verification.digest;
    state.previousKeyId = verification.keyId;
    $('#previousPolicyStatus').textContent = `Valid predecessor: ${verification.digest}`;
    $('#previousPolicyStatus').className = 'inline-status good';
    toast('Previous policy linked into the continuity chain.', 'success');
  } catch (error) {
    state.previousHash = null;
    state.previousKeyId = null;
    $('#previousPolicyStatus').textContent = error?.message || 'Invalid previous policy.';
    $('#previousPolicyStatus').className = 'inline-status bad';
  }
}

async function verifyUploaded() {
  const file = $('#verifyFile').files[0];
  const box = $('#verifyResult');
  if (!file) return;
  box.className = 'verify-output working';
  box.innerHTML = '<strong>Checking signature…</strong>';
  try {
    const document = JSON.parse(await file.text());
    const result = await verifyDocument(document);
    const summary = summarizePolicy(document);
    if (result.valid) {
      box.className = 'verify-output valid';
      box.innerHTML = `
        <div class="verify-title">✓ Cryptographically valid</div>
        <p>The payload hash matches and the ECDSA P-256 signature verifies against the embedded public key.</p>
        <dl class="mini-dl">
          <div><dt>Key</dt><dd>${escapeHtml(result.keyId)}</dd></div>
          <div><dt>Payload</dt><dd>${escapeHtml(result.digest)}</dd></div>
          <div><dt>Rules</dt><dd>${summary.total} total · ${summary.deny} deny · ${summary.approval} approval</dd></div>
          <div><dt>Unknown actions</dt><dd>${escapeHtml(summary.unknown)}</dd></div>
        </dl>`;
    } else {
      box.className = 'verify-output invalid';
      box.innerHTML = `<div class="verify-title">✕ Not valid</div><p>${escapeHtml(result.reason)}</p>`;
    }
  } catch (error) {
    box.className = 'verify-output invalid';
    box.innerHTML = `<div class="verify-title">✕ Could not verify</div><p>${escapeHtml(error?.message || String(error))}</p>`;
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' }[c]));
}

function installEvents() {
  $$('[data-next]').forEach(btn => btn.addEventListener('click', () => setStep(state.step + 1)));
  $$('[data-back]').forEach(btn => btn.addEventListener('click', () => setStep(state.step - 1)));
  $$('.preset').forEach(btn => btn.addEventListener('click', () => applyPreset(btn.dataset.preset)));
  $('#generateBtn').addEventListener('click', generatePolicy);
  $('#loadExistingKeyBtn').addEventListener('click', importKeyBundle);
  $('#previousPolicyFile').addEventListener('change', importPreviousPolicy);
  $('#verifyFile').addEventListener('change', verifyUploaded);

  $('#downloadPolicyBtn').addEventListener('click', () => state.document && downloadJson('sovereignty.json', state.document));
  $('#downloadKeyBtn').addEventListener('click', () => state.keyBundle && downloadJson('sovereignroot-key.json', state.keyBundle));
  $('#downloadGuideBtn').addEventListener('click', () => state.document && downloadText('SOVEREIGNROOT-INSTALL.md', installGuide(state.document), 'text/markdown'));
  $('#copyGuideBtn').addEventListener('click', async () => {
    if (!state.document) return;
    const ok = await copyText(installGuide(state.document));
    toast(ok ? 'Install instructions copied.' : 'Copy unavailable — use the download instead.', ok ? 'success' : 'error');
  });
  $('#copyJsonBtn').addEventListener('click', async () => {
    if (!state.document) return;
    const ok = await copyText(JSON.stringify(state.document, null, 2));
    toast(ok ? 'JSON copied.' : 'Copy unavailable — use the download instead.', ok ? 'success' : 'error');
  });

  $$('[data-scroll]').forEach(el => el.addEventListener('click', e => {
    const target = $(el.dataset.scroll);
    if (target) { e.preventDefault(); target.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  }));

  $('#childAgents').addEventListener('change', e => {
    $('#childDepth').disabled = !e.target.checked;
  });

  $('#policyForm').addEventListener('submit', e => e.preventDefault());
}

function featureDetect() {
  const secure = !!globalThis.crypto?.subtle;
  $('#cryptoSupport').textContent = secure ? (location.protocol === 'file:' ? 'Local crypto ready' : 'Web Crypto ready') : 'Web Crypto unavailable';
  $('#cryptoSupport').className = `status-chip ${secure ? 'valid' : 'warning'}`;
}

function registerServiceWorker() {
  if (location.protocol !== 'file:' && 'serviceWorker' in navigator && window.isSecureContext) {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }
}

function init() {
  installEvents();
  applyPreset('balanced');
  setStep(1);
  featureDetect();
  registerServiceWorker();
  document.documentElement.dataset.appReady = 'true';
  // Mark the first real user interaction so setStep only scrolls on demand.
  const mark = () => { state._userInteracted = true; };
  ['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach(evt =>
    document.addEventListener(evt, mark, { once: true, passive: true }));
}

init();

})();
