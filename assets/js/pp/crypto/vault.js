// assets/js/pp/crypto/vault.js
import { idbGet, idbPut } from './idb.js';

export async function vaultPutFileKey(fileOid, cryptoKey) {
  await idbPut('vault_files', fileOid, cryptoKey);
}
export async function vaultGetFileKey(fileOid) {
  return idbGet('vault_files', fileOid);
}

export async function vaultPutDirKey(dirOid, cryptoKey) {
  await idbPut('vault_dirs', dirOid, cryptoKey);
}
export async function vaultGetDirKey(dirOid) {
  return idbGet('vault_dirs', dirOid);
}

export async function vaultDelFileKey(oid) {
  const db = await _db();                         // whatever your db opener is named
  const tx = db.transaction('vault_files', 'readwrite');
  tx.objectStore('vault_files').delete(oid);
  await tx.complete?.();                          // ignore if not present in your wrapper
}

