// assets/js/pp/init-keys.js
import { ensureIdentity, exportPublicJwks } from './crypto/keys.js';
import { idbDel, idbPut } from './crypto/idb.js';
import { postJson } from './api.js';

const KEYS_STORE = 'keys';
const ID_ECDH = 'identity:ecdh';
const ID_ECDSA = 'identity:ecdsa';

// 1) Migrate legacy localStorage.privateKey (if present) into IndexedDB as NON-extractable
async function migrateLegacyLocalStorageKey() {
  try {
    const raw = localStorage.getItem('privateKey');
    if (!raw) return false;

    const jwk = JSON.parse(raw);
    // Expect a private JWK for ECDH with d, x, y
    if (!jwk || jwk.kty !== 'EC' || !jwk.d || !jwk.x || !jwk.y) {
      // Not a usable private JWK; just purge it
      localStorage.removeItem('privateKey');
      document.cookie = 'public_key=; Max-Age=0; path=/';
      console.warn('[PP] Legacy privateKey present but not a valid EC private JWK. Purged.');
      return false;
    }

    const crv = jwk.crv || 'P-256';

    // Import NON-extractable private key
    const priv = await crypto.subtle.importKey(
      'jwk', jwk, { name: 'ECDH', namedCurve: crv }, /*extractable*/ false, ['deriveBits','deriveKey']
    );

    // Build & import matching public key JWK from x/y
    const pubJwk = { kty: 'EC', crv, x: jwk.x, y: jwk.y, ext: true, key_ops: [] };
    const pub = await crypto.subtle.importKey(
      'jwk', pubJwk, { name: 'ECDH', namedCurve: crv }, /*extractable*/ true, []
    );

    await idbPut(KEYS_STORE, ID_ECDH, { publicKey: pub, privateKey: priv });

    // Purge legacy stores
    localStorage.removeItem('privateKey');
    document.cookie = 'public_key=; Max-Age=0; path=/';

    console.info('[PP] Migrated legacy localStorage.privateKey into IndexedDB and purged legacy copies.');
    return true;
  } catch (e) {
    console.warn('[PP] Migration of legacy localStorage.privateKey failed; purging.', e);
    try { localStorage.removeItem('privateKey'); } catch(_) {}
    document.cookie = 'public_key=; Max-Age=0; path=/';
    return false;
  }
}

// 2) Rotate legacy EXTRACTABLE identity keys in IDB (delete wrong names too)
async function rotateIfLegacyExtractable() {
  const id = await ensureIdentity(); // whatever is there (post-migration, or generated)
  if (id?.ecdh?.privateKey?.extractable || id?.ecdsa?.privateKey?.extractable) {
    // Delete BOTH colon and dot names to be safe
    const names = ['identity:ecdh', 'identity:ecdsa', 'identity.ecdh', 'identity.ecdsa'];
    for (const n of names) {
      try { await idbDel(KEYS_STORE, n); } catch(_) {}
    }
    // Regenerate (keys.js uses extractable:false), publish public JWKs
    const fresh = await ensureIdentity();
    const jwks  = await exportPublicJwks();
    await postJson('/api/keys/publish', jwks);
    console.warn('[PP] Rotated legacy extractable identity keys in IndexedDB.');
  }
}

(async () => {
  try {
    await migrateLegacyLocalStorageKey();
    await rotateIfLegacyExtractable();   // in case something extractable survived

    // Ensure identity exists, then publish public keys (idempotent)
    await ensureIdentity();
    const jwks = await exportPublicJwks();
    await postJson('/api/keys/publish', jwks);

    // Final hygiene: make sure legacy artifacts are gone
    try { localStorage.removeItem('privateKey'); } catch(_) {}
    document.cookie = 'public_key=; Max-Age=0; path=/';

    console.debug('[PP] Identity ok; public keys published.');
  } catch (e) {
    console.error('[PP] init-keys failed:', e);
  }
})();
