import assert from 'node:assert/strict';
import {
  canonicalize, generateSigningKeyPair, exportPublicJwk, exportPrivateJwk,
  keyIdFromPublicJwk, signDocument, verifyDocument, encryptPrivateJwk, decryptPrivateJwk
} from '../js/crypto.js';
import { PRESETS, buildSovereigntyPayload } from '../js/policy.js';
import { evaluateRoot, intersectDecision } from '../reference/policy-engine.mjs';

console.log('SovereignRoot tests');

// Deterministic object ordering / JSON serialization.
assert.equal(canonicalize({b:1,a:2}), '{"a":2,"b":1}');
assert.equal(canonicalize({z:[{b:true,a:null}],a:'x'}), '{"a":"x","z":[{"a":null,"b":true}]}');
assert.throws(() => canonicalize(-0), /Negative zero/);
assert.throws(() => canonicalize(NaN), /NaN/);
console.log('✓ canonicalization guards');

const pair = await generateSigningKeyPair();
const pub = await exportPublicJwk(pair.publicKey);
const privJwk = await exportPrivateJwk(pair.privateKey);
const kid = await keyIdFromPublicJwk(pub);
assert.match(kid, /^urn:ietf:params:oauth:jwk-thumbprint:sha-256:/);
console.log('✓ signing identity');

const form = {
  ...PRESETS.balanced,
  displayName: 'Test Holder',
  impersonation: 'deny',
  legalAcceptance: 'require_approval',
  bulkExport: 'require_approval',
  blockedRecipients: 'blocked@example.com',
  blockedDomains: 'blocked.example'
};
const payload = buildSovereigntyPayload(form, pub, kid, null);
const signed = await signDocument(payload, pair.privateKey, kid);
let result = await verifyDocument(signed);
assert.equal(result.valid, true, result.reason);
console.log('✓ sign and verify');

const tampered = structuredClone(signed);
tampered.semantics.unknown_action = 'allow';
result = await verifyDocument(tampered);
assert.equal(result.valid, false);
console.log('✓ tamper detection');

const bundle = await encryptPrivateJwk(privJwk, 'correct horse battery staple');
const recovered = await decryptPrivateJwk(bundle, 'correct horse battery staple');
assert.equal(recovered.d, privJwk.d);
await assert.rejects(() => decryptPrivateJwk(bundle, 'wrong passphrase here'), /Unable to decrypt/);
console.log('✓ encrypted key round-trip');

let d = evaluateRoot(signed, {category:'secrets',operation:'transmit_secret'});
assert.equal(d.decision, 'deny');
d = evaluateRoot(signed, {category:'finance',operation:'transfer_value',currency:'GBP',amount_minor:'10001'});
assert.equal(d.decision, 'require_approval');
d = evaluateRoot(signed, {category:'network',operation:'connect_domain',domain:'sub.blocked.example'});
assert.equal(d.decision, 'deny');
d = evaluateRoot(signed, {category:'communications',operation:'contact_recipient',recipient:'blocked@example.com'});
assert.equal(d.decision, 'deny');
assert.equal(intersectDecision('allow','deny'), 'deny');
assert.equal(intersectDecision('require_approval','allow'), 'require_approval');
console.log('✓ policy precedence and conditions');

console.log('\nAll tests passed.');
