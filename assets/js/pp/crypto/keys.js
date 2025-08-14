// static/js/pp/crypto/keys.js
import { idbGet, idbPut } from './idb.js';

const K_STORE = 'keys';
const K_ECDSA = 'identity:ecdsa';
const K_ECDH  = 'identity:ecdh';

/** Generate identity keys (ECDSA for signatures, ECDH for key agreement). */
async function generateIdentityKeys() {
  // NOTE: extractable=true allows exporting the *public* keys as JWK.
  // We will NOT export or persist private keys outside IndexedDB.
  const ecdsa = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign', 'verify']
  );
  const ecdh = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveKey', 'deriveBits']
  );
  return { ecdsa, ecdh };
}

/** Persist keypair into IndexedDB under fixed keys. */
async function persistIdentity({ ecdsa, ecdh }) {
  // CryptoKey objects can be stored in IndexedDB directly.
  await idbPut(K_STORE, K_ECDSA, ecdsa);
  await idbPut(K_STORE, K_ECDH,  ecdh);
}

/** Load identity keypairs from IndexedDB. */
export async function loadIdentity() {
  const ecdsa = await idbGet(K_STORE, K_ECDSA);
  const ecdh  = await idbGet(K_STORE, K_ECDH);
  return (ecdsa && ecdh) ? { ecdsa, ecdh } : null;
}

/** Ensure identity exists: if missing, generate and persist it. */
export async function ensureIdentity() {
  const k = await loadIdentity();
  if (k) return k;
  const fresh = await generateIdentityKeys();
  await persistIdentity(fresh);
  return fresh;
}

/** Export PUBLIC JWKs so we can publish them server-side later. */
export async function exportPublicJwks() {
  const id = await loadIdentity();
  if (!id) throw new Error('Identity not initialized');
  const ecdsaJwk = await crypto.subtle.exportKey('jwk', id.ecdsa.publicKey);
  const ecdhJwk  = await crypto.subtle.exportKey('jwk', id.ecdh.publicKey);
  return { ecdsa: ecdsaJwk, ecdh: ecdhJwk };
}

export async function signBytesECDSA(privateKey, bytesU8) {
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, bytesU8);
  return new Uint8Array(sig);
}

export async function importEcdsaPubJwk(jwk) {
  return crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
true, ['verify']
  );
}

export async function verifyBytesECDSA(publicKey, bytesU8, sigU8) {
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, sigU8, bytesU8);
}

