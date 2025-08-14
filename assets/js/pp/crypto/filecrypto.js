// assets/js/pp/crypto/filecrypto.js
export async function genFileKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt','decrypt']);
}
export async function genDirKey() { return genFileKey(); }

export async function encryptName(aesKey, nameStr) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = new TextEncoder().encode(nameStr);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, pt);
  return { iv, ciphertext: new Uint8Array(ct) };
}
export async function decryptName(aesKey, iv, encBytes) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, encBytes);
  return new TextDecoder().decode(pt);
}

// --- NEW helper: AAD encoder ---
function encodeAAD({ fileOid, index, total, version = 1 }) {
  const enc = new TextEncoder();
  const prefix = enc.encode(`pp:v1|${fileOid}|`);
  const u32 = new Uint8Array(12); // 3 * 4 bytes
  const dv = new DataView(u32.buffer);
  dv.setUint32(0, index,  false);
  dv.setUint32(4, total,  false);
  dv.setUint32(8, version, false);
  const out = new Uint8Array(prefix.length + u32.length);
  out.set(prefix, 0); out.set(u32, prefix.length);
  return out;
}

// --- PATCH: encrypt a chunk with AAD ---
export async function encryptChunk(aesKey, plainU8, aadCtx) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const params = { name: 'AES-GCM', iv };
  const additionalData = encodeAAD(aadCtx); // <- bind to file+index+total
   if (additionalData) params.additionalData = additionalData;
  const ct = await crypto.subtle.encrypt(params, aesKey, plainU8);
  return { iv, ciphertext: new Uint8Array(ct) };
}

// --- PATCH: decrypt bytes with AAD ---
// Decrypt AES-GCM bytes (fail if AAD doesn't match)
export async function decryptBytes(aesKey, ivU8, ctU8, aadCtx) {
  const params = { name: 'AES-GCM', iv: ivU8 };
  const additionalData = encodeAAD(aadCtx);
  if (additionalData) params.additionalData = additionalData;
  const pt = await crypto.subtle.decrypt(params, aesKey, ctU8);
   return new Uint8Array(pt);
 }

// URL-safe base64 helpers
export function b64e(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
}
export function b64eIV(iv) { return b64e(new Uint8Array(iv)); }

export function b64dToU8(b64url) {
  const pad = (s) => s + '==='.slice((s.length + 3) % 4);
  const std = pad(b64url.replaceAll('-','+').replaceAll('_','/'));
  const bin = atob(std);
  const u8 = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

// --- Hash + Merkle helpers (used by part B) ---
export async function hashU8(u8) {
  const d = await crypto.subtle.digest('SHA-256', u8);
  return new Uint8Array(d);
}

export async function merkleRoot(leaves /* Array<Uint8Array> */) {
  if (!leaves || leaves.length === 0) return new Uint8Array(32); // 32 zero bytes
  let level = leaves.slice();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const L = level[i];
      const R = (i + 1 < level.length) ? level[i + 1] : level[i];
      const cat = new Uint8Array(L.length + R.length);
      cat.set(L, 0); cat.set(R, L.length);
      next.push(await hashU8(cat));
    }
    level = next;
  }
  return level[0];
}
