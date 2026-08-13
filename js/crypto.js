const te = new TextEncoder();
const td = new TextDecoder();

export function bytesToBase64Url(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlToBytes(value) {
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

export function canonicalize(value) {
  return canonicalizeInner(value);
}

export async function sha256Bytes(data) {
  const bytes = typeof data === 'string' ? te.encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export async function sha256Base64Url(data) {
  return bytesToBase64Url(await sha256Bytes(data));
}

export async function sha256Hex(data) {
  return [...await sha256Bytes(data)].map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function generateSigningKeyPair() {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
}

export async function exportPublicJwk(publicKey) {
  const jwk = await crypto.subtle.exportKey('jwk', publicKey);
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, alg: 'ES256', key_ops: ['verify'], ext: true };
}

export async function exportPrivateJwk(privateKey) {
  return crypto.subtle.exportKey('jwk', privateKey);
}

export async function importPublicJwk(jwk) {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
}

export async function importPrivateJwk(jwk) {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign']
  );
}

export async function jwkThumbprint(publicJwk) {
  const core = { crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y };
  return sha256Base64Url(canonicalize(core));
}

export async function keyIdFromPublicJwk(publicJwk) {
  return `urn:ietf:params:oauth:jwk-thumbprint:sha-256:${await jwkThumbprint(publicJwk)}`;
}

export function unsignedPayload(document) {
  const clone = structuredClone(document);
  delete clone.proof;
  return clone;
}

export async function signDocument(document, privateKey, keyId) {
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

export async function verifyDocument(document) {
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

export async function encryptPrivateJwk(privateJwk, passphrase) {
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

export async function decryptPrivateJwk(bundle, passphrase) {
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

export function downloadJson(filename, object) {
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

export function downloadText(filename, text, type = 'text/plain') {
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
