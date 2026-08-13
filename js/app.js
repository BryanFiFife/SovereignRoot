import {
  generateSigningKeyPair, exportPublicJwk, exportPrivateJwk, importPrivateJwk,
  keyIdFromPublicJwk, signDocument, verifyDocument, encryptPrivateJwk, decryptPrivateJwk,
  downloadJson, downloadText
} from './crypto.js';
import { PRESETS, buildSovereigntyPayload, summarizePolicy, installGuide } from './policy.js';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const state = {
  step: 1,
  document: null,
  keyBundle: null,
  privateKey: null,
  publicJwk: null,
  previousHash: null,
  previousKeyId: null
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
  $('#generator')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
    await navigator.clipboard.writeText(installGuide(state.document));
    toast('Install instructions copied.', 'success');
  });
  $('#copyJsonBtn').addEventListener('click', async () => {
    if (!state.document) return;
    await navigator.clipboard.writeText(JSON.stringify(state.document, null, 2));
    toast('JSON copied.', 'success');
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
  const secure = window.isSecureContext && !!globalThis.crypto?.subtle;
  $('#cryptoSupport').textContent = secure ? 'Web Crypto ready' : 'HTTPS/localhost required';
  $('#cryptoSupport').className = `status-chip ${secure ? 'valid' : 'warning'}`;
}

function registerServiceWorker() {
  if ('serviceWorker' in navigator && window.isSecureContext) {
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
}

init();
