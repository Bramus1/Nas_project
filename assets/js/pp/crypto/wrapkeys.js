import { ensureIdentity } from './keys.js';
import { getJson } from '../api.js';
import { hkdfToAesGcm } from './chatcrypto.js';

// OWNER side: wrap raw AES file key for recipient, and include a snapshot of owner's ECDH pub JWK
export async function wrapFileKeyForRecipient(fileOid, fileKey, recipientUsername, ownerUsername) {
  const info = `pp-file-wrap-v1|${fileOid}|owner:${ownerUsername}|recipient:${recipientUsername}`;
  const { ecdh } = await ensureIdentity();

  // recipient's current ECDH pubkey
  const res = await getJson(`/api/keys/of/${encodeURIComponent(recipientUsername)}`);
  if (!res?.ecdh) throw new Error('peer ECDH public key not found');
  const peerPub = await crypto.subtle.importKey('jwk', res.ecdh, { name: 'ECDH', namedCurve: 'P-256' }, false, []);

  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerPub }, ecdh.privateKey, 256);
  const kek  = await hkdfToAesGcm(bits, info);

  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', fileKey));
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, raw));

  // snapshot the owner's CURRENT ECDH pub JWK (so recipients can unwrap even after rotation)
  const owner_pub_jwk = await crypto.subtle.exportKey('jwk', ecdh.publicKey);

  return { iv, ct, owner_pub_jwk };
}

// RECIPIENT side: unwrap using the SNAPSHOT owner_pub_jwk if provided, else fallback to current
// unwrapMyFileKey(fileOid, ownerUsername, recipientUsername, ownerPubJwk, wrap_iv_u8, wrapped_key_u8)
export async function unwrapMyFileKey(fileOid, ownerUsername, recipientUsername, ownerPubJwk, wrap_iv_u8, wrapped_key_u8) {
  const info = `pp-file-wrap-v1|${fileOid}|owner:${ownerUsername}|recipient:${recipientUsername}`;
  const { ecdh } = await ensureIdentity();

  let ownerPubKey;
  if (ownerPubJwk) {
    ownerPubKey = await crypto.subtle.importKey('jwk', ownerPubJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  } else {
    // backward-compat for older shares: fetch the owner's current pub key
    const resOwner = await getJson(`/api/keys/of/${encodeURIComponent(ownerUsername)}`);
    if (!resOwner?.ecdh) throw new Error('owner ECDH public key not found');
    ownerPubKey = await crypto.subtle.importKey('jwk', resOwner.ecdh, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  }

  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: ownerPubKey }, ecdh.privateKey, 256);
  const kek  = await hkdfToAesGcm(bits, info);

  const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: wrap_iv_u8 }, kek, wrapped_key_u8);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt','decrypt']);
}
