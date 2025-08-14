// assets/js/pp/crypto/chatcrypto.js
import { ensureIdentity } from './keys.js';
import { getJson } from '../api.js';

// ⬇️ export this so wrapkeys.js can import it
export async function hkdfToAesGcm(sharedSecretRaw, infoStr) {
  const baseKey = await crypto.subtle.importKey('raw', sharedSecretRaw, 'HKDF', false, ['deriveKey']);
  const salt = new Uint8Array(32); // zeros are fine; uniqueness comes from ECDH inputs + per-message IVs
  const info = new TextEncoder().encode(infoStr);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt','decrypt']
  );
}

async function deriveSessionKeyWith(userName) {
  // our identity (IndexedDB)
  const { ecdh } = await ensureIdentity();

  // recipient public ECDH key from server
  const res = await getJson(`/api/keys/of/${encodeURIComponent(userName)}`);
  if (!(res?.ecdh)) throw new Error('Recipient ECDH public key not found.');
  const recipientPub = await crypto.subtle.importKey(
    'jwk', res.ecdh, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );

  // ECDH -> raw bits
  const bits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: recipientPub }, ecdh.privateKey, 256
  );

  // HKDF → AES-GCM session key
  return hkdfToAesGcm(bits, 'pp-chat-v1');
}

export async function chatEncryptFor(userName, plaintextU8) {
  const key = await deriveSessionKeyWith(userName);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintextU8)
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0); out.set(ct, iv.length);
  return out.buffer;
}

export async function chatDecryptFrom(userName, ivPlusCtBuffer) {
  const key = await deriveSessionKeyWith(userName);
  const buf = new Uint8Array(ivPlusCtBuffer);
  const iv = buf.slice(0, 12);
  const ct = buf.slice(12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return pt;
}
