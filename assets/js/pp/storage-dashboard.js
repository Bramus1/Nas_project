// assets/js/pp/storage-dashboard.js
import { postJson, getJson } from './api.js';
import {
  genFileKey, genDirKey, encryptName, decryptName,
  encryptChunk, decryptBytes, b64e, b64eIV, b64dToU8,merkleRoot, hashU8
} from './crypto/filecrypto.js';
import { vaultPutFileKey, vaultGetFileKey, vaultPutDirKey, vaultGetDirKey } from './crypto/vault.js';
import { wrapFileKeyForRecipient, unwrapMyFileKey } from './crypto/wrapkeys.js';
import { ensureIdentity, importEcdsaPubJwk, verifyBytesECDSA } from './crypto/keys.js?v=2';


console.log('[dashboard] script loaded');
window.addEventListener('error', e => console.error('[global error]', e.message));
window.addEventListener('unhandledrejection', e => console.error('[unhandled]', e.reason));

const CHUNK = 64 * 1024; // 64 KiB
let currentParent = null; // null = root
let breadcrumb = []; // [{oid, name}]

function el(sel){ return document.querySelector(sel); }
function h(html){ const d=document.createElement('div'); d.innerHTML=html.trim(); return d.firstChild; }
function log(msg){ const out=el('#pp-drive-log'); if(out){ out.textContent += msg + '\n'; } }

// ---- API wrappers ----
async function listDir(parentOid) {
  const q = parentOid ? `?parent=${encodeURIComponent(parentOid)}` : '';
  return getJson(`/api/dir/list${q}`);
}
async function initFile(directory_oid, enc_name, name_iv, size_bytes) {
  return postJson('/api/file/init', { directory_oid, enc_name, name_iv, size_bytes });
}
async function sendChunk(file_oid, upload_token, index, iv_u8, ct_u8, length) {
  return postJson('/api/file/chunk', {
    file_oid, upload_token, index,
    iv: b64e(iv_u8), ciphertext: b64e(ct_u8), length
  });
}
async function finalizeFile(file_oid, upload_token, chunk_count, manifest) {
  const body = { file_oid, upload_token, chunk_count };
  if (manifest) body.manifest = manifest;
  return postJson('/api/file/finalize', body);
 }

async function metaFile(oid) { return getJson(`/api/file/meta/${oid}`); }
async function fetchChunk(oid, index) { return getJson(`/api/file/chunk/${oid}/${index}`); }

// ---- Actions ----
async function createFolder() {
  const name = prompt('Folder name:');
  if (!name) return;
  const dKey = await genDirKey();
  const { iv, ciphertext } = await encryptName(dKey, name);
  const r = await postJson('/api/dir/create', {
    parent_oid: currentParent,
    enc_name: b64e(ciphertext),
    name_iv: b64eIV(iv)
  });
  await vaultPutDirKey(r.oid, dKey);
  await refresh();
}

async function uploadOne(file) {
  const fKey = await genFileKey();
  const encName = await encryptName(fKey, file.name);

  const init = await initFile(currentParent, b64e(encName.ciphertext), b64eIV(encName.iv), file.size);
  const { file_oid, upload_token } = init;
  await vaultPutFileKey(file_oid, fKey);

  log(`Uploading ${file.name} → ${file_oid}`);

  let sent = 0, index = 0;
  const totalChunks = Math.ceil(file.size / CHUNK);
  const leafHashes = [];
  while (sent < file.size) {
    const blob = file.slice(sent, Math.min(file.size, sent + CHUNK));
    const buf = new Uint8Array(await blob.arrayBuffer());
    const aadCtx = { fileOid: file_oid, index, total: totalChunks, version: 1 };
    const { iv, ciphertext } = await encryptChunk(fKey, buf, aadCtx);
    await sendChunk(file_oid, upload_token, index, new Uint8Array(iv), ciphertext, buf.length);
    leafHashes.push(await hashU8(ciphertext));
    sent += buf.length; index += 1;
  }
  const root = await merkleRoot(leafHashes);
  const manifest = { algo: 'sha256', n: totalChunks, root_b64: b64e(root), version: 1 };
  await finalizeFile(file_oid, upload_token, totalChunks, manifest);
  log(`Done: ${file.name}`);
}

async function openFolder(dir) {
  currentParent = dir.oid;
  breadcrumb.push(dir);
  await refresh();
}

async function goRoot() {
  currentParent = null;
  breadcrumb = [];
  await refresh();
}

async function goUp() {
  breadcrumb.pop();
  currentParent = breadcrumb.length ? breadcrumb[breadcrumb.length-1].oid : null;
  await refresh();
}

async function downloadFile(file) {
  const fKey = await vaultGetFileKey(file.oid);
  if (!fKey) return alert('Missing file key on this device.');
  const name = await decryptName(fKey, b64dToU8(file.name_iv), b64dToU8(file.enc_name));

  const meta = await metaFile(file.oid);
  let total = meta.chunk_count >>> 0;
  const expectedRoot = meta.manifest_root ? b64dToU8(meta.manifest_root) : null;
  const manifestSig  = meta.manifest_sig  ? b64dToU8(meta.manifest_sig)  : null;

  const parts = [];
  const leafHashes = [];
  for (let i=0; i<total; i++){
    const ch = await fetchChunk(file.oid, i);
    const iv = b64dToU8(ch.iv);
    const ct = b64dToU8(ch.ciphertext);
    const aadCtx = { fileOid: file.oid, index: i, total, version: 1 };
    const pt = await decryptBytes(fKey, iv, ct, aadCtx);
    leafHashes.push(await hashU8(ct));
    parts.push(pt);
  }
  if (expectedRoot) {
    const root = await merkleRoot(leafHashes);
    const ok = root.length === expectedRoot.length && root.every((b,k)=>b===expectedRoot[k]);
    if (!ok) throw new Error('Integrity error: Merkle root mismatch');
    // Non-repudiation: verify owner's signature on the manifest (owner = me)
    if (manifestSig) {
      try {
        const enc = new TextEncoder();
        const toVerify = enc.encode(`pp:manifest|${file.oid}|sha256|${total}|${meta.manifest_root}|v1`);
        const {ecdsa} = await ensureIdentity(); // my identity
        const myPubJwk = await crypto.subtle.exportKey('jwk', ecdsa.publicKey);
        const pub = await importEcdsaPubJwk(myPubJwk);
        const okSig = await verifyBytesECDSA(pub, toVerify, manifestSig);
        if (!okSig) throw new Error('Non-repudiation failure: bad manifest signature');
      } catch (e) {
        console.warn('Manifest signature verification failed:', e);
        alert('Manifest signature verification failed: ' + e.message);
      }
    }
  }
  total = parts.reduce((n,a)=>n+a.length,0);
  const joined = new Uint8Array(total);
  let off=0; for (const p of parts){ joined.set(p, off); off+=p.length; }
  const blob = new Blob([joined], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}

async function shareFile(f) {
  try {
    const to = prompt('Share with username (must be an accepted friend):');
    if (!to) return;

    let fKey = await vaultGetFileKey(f.oid);
    if (!fKey) return alert('Missing local file key for this file on this device.');

    const me = window?.CURRENT_USERNAME; // defined in Base.html
    if (!me) return alert('CURRENT_USERNAME not set on page.');

    const { iv, ct ,owner_pub_jwk} = await wrapFileKeyForRecipient(f.oid, fKey, to, me);
    await postJson('/api/share/create', {
      file_oid: f.oid,
      username: to,
      wrap_iv: b64e(iv),
      wrapped_key: b64e(ct),
      owner_pub_jwk,
    });

    log(`Shared ${f.oid} → ${to}`);
    alert('Shared!');
  } catch (e) {
    console.error(e); alert('Share failed: ' + e.message);
  }
}

async function unlockSharedName(s) {
  try {
    const k = await getJson(`/api/share/mykey/${s.file_oid}`);
   const me = window.CURRENT_USERNAME;            // your username from Base.html
   const fKey = await unwrapMyFileKey(
    s.file_oid, k.owner, me, k.owner_pub_jwk,
    b64dToU8(k.wrap_iv), b64dToU8(k.wrapped_key));
    await vaultPutFileKey(s.file_oid, fKey);
    await refresh();
  } catch (e) {
    console.error(e); alert('Unlock failed: ' + e.message);
  }
}

async function downloadSharedFile(s) {
  let fKey = await vaultGetFileKey(s.file_oid);
  if (!fKey) {
     const k = await getJson(`/api/share/mykey/${s.file_oid}`);
const me = window.CURRENT_USERNAME;
   fKey = await unwrapMyFileKey(
    s.file_oid, k.owner, me, k.owner_pub_jwk,
   b64dToU8(k.wrap_iv), b64dToU8(k.wrapped_key)
  );
    await vaultPutFileKey(s.file_oid, fKey);
  }
  const name = await decryptName(fKey, b64dToU8(s.name_iv), b64dToU8(s.enc_name));

  const meta = await metaFile(s.file_oid);
  let total = meta.chunk_count >>> 0;
  const expectedRoot = meta.manifest_root ? b64dToU8(meta.manifest_root) : null;
  const manifestSig  = meta.manifest_sig  ? b64dToU8(meta.manifest_sig)  : null;
  const leafHashes = [];
    const parts = [];
  for (let i=0; i<total; i++){
    const ch = await fetchChunk(s.file_oid, i);
    const iv = b64dToU8(ch.iv);
    const ct = b64dToU8(ch.ciphertext);
    const aadCtx = { fileOid: s.file_oid, index: i, total, version: 1 };
    const pt = await decryptBytes(fKey, iv, ct, aadCtx);
    leafHashes.push(await hashU8(ct));
    parts.push(pt);
  }
  if (expectedRoot) {
    const root = await merkleRoot(leafHashes);
    const ok = root.length === expectedRoot.length && root.every((b,k)=>b===expectedRoot[k]);
    if (!ok) throw new Error('Integrity error: Merkle root mismatch');
    // Non-repudiation: verify owner's signature on the manifest (owner = me)
    if (manifestSig) {
      try{
      const resOwner = await getJson(`/api/keys/of/${encodeURIComponent(s.owner)}`);
      if (!resOwner?.ecdsa) throw new Error('Owner ECDSA public key not found');
      const ownerEcdsaJwk = resOwner.ecdsa;
      // If not present, call a small endpoint like `/api/keys/of/${k.owner}` to get it.
     // const ownerEcdsaJwk = /* TODO: put your actual owner ECDSA JWK here */;
      const pub = await importEcdsaPubJwk(ownerEcdsaJwk);
      const enc = new TextEncoder();
      const toVerify = enc.encode(`pp:manifest|${s.file_oid}|sha256|${total}|${meta.manifest_root}|v1`);
      const okSig = await verifyBytesECDSA(pub, toVerify, manifestSig);
      if (!okSig) throw new Error('Non-repudiation failure: bad manifest signature');
    }catch (e){
      console.warn('Manifest signature verification failed:', e);}
      alert('Manifest signature verification failed: ' + e.message);
    }
  }
  const totalBytes = parts.reduce((n,a)=>n+a.length,0);
  const joined = new Uint8Array(totalBytes);
  let off=0; for (const p of parts){ joined.set(p, off); off+=p.length; }
  const blob = new Blob([joined], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}

// ---- Render ----
async function refresh() {
  const out = el('#pp-drive-list');
  const bc  = el('#pp-drive-bc');
  out.innerHTML = '';
  bc.innerHTML = '';

  // Breadcrumb
  const rootBtn = h(`<button class="pp-btn">Root</button>`);
  rootBtn.onclick = goRoot;
  bc.appendChild(rootBtn);
  for (let i=0;i<breadcrumb.length;i++){
    const b = breadcrumb[i];
    const btn = h(`<button class="pp-btn">${escapeHtml(b.name)}</button>`);
    btn.onclick = async () => {
      breadcrumb = breadcrumb.slice(0, i+1);
      currentParent = b.oid;
      await refresh();
    };
    bc.appendChild(btn);
  }

  const data = await listDir(currentParent);

  // Directories
  for (const d of data.dirs) {
    let name = '[locked]';
    const dKey = await vaultGetDirKey(d.oid);
    if (dKey) {
      try { name = await decryptName(dKey, b64dToU8(d.name_iv), b64dToU8(d.enc_name)); }
      catch { name = '[decrypt error]'; }
    }
    const row = h(`
      <div class="pp-row">
        <span class="pp-emoji">📁</span>
        <span class="pp-name">${escapeHtml(name)}</span>
        <span class="pp-actions">
          <button class="pp-btn pp-open">Open</button>
          <button class="pp-btn pp-dirdel">Delete</button>
        </span>
      </div>
    `);
    row.querySelector('.pp-open').onclick = () => openFolder({ oid: d.oid, name });
    row.querySelector('.pp-dirdel').onclick = () => deleteDirectory(d);
    out.appendChild(row);
  }

  // Files (yours)
  for (const f of data.files) {
    let name = '[locked]';
    const fKey = await vaultGetFileKey(f.oid);
    if (fKey) {
      try { name = await decryptName(fKey, b64dToU8(f.name_iv), b64dToU8(f.enc_name)); }
      catch { name = '[decrypt error]'; }
    }
    const row = h(`
      <div class="pp-row">
        <span class="pp-emoji">📄</span>
        <span class="pp-name">${escapeHtml(name)}</span>
        <span class="pp-meta">${f.size_bytes} bytes • ${f.chunk_count} chunks</span>
        <span class="pp-actions">
          <button class="pp-btn pp-dl">Download</button>
          <button class="pp-btn pp-share">Share</button>
          <button class="pp-btn pp-del">Delete</button>
        </span>
      </div>
    `);
    row.querySelector('.pp-dl').onclick = () => downloadFile(f);
    row.querySelector('.pp-share').onclick = () => shareFile(f);
    row.querySelector('.pp-del').onclick = () => deleteFile(f);
    out.appendChild(row);
  }

  // Shared with me
  const shared = await getJson('/api/share/list');
  if (shared.items.length) {
    out.appendChild(h(`<div style="margin-top:12px;font-weight:700;">Shared with you</div>`));
  }
  for (const s of shared.items) {
    let name = '[locked]';
    let fKey = await vaultGetFileKey(s.file_oid);
    if (fKey) {
      try { name = await decryptName(fKey, b64dToU8(s.name_iv), b64dToU8(s.enc_name)); }
      catch { name = '[decrypt error]'; }
    }
    const row = h(`
      <div class="pp-row">
        <span class="pp-emoji">📄</span>
        <span class="pp-name">${escapeHtml(name)}</span>
        <span class="pp-meta">${s.size_bytes} bytes • ${s.chunk_count} chunks • by ${escapeHtml(s.owner)}</span>
        <span class="pp-actions">
          <button class="pp-btn pp-dl">Download</button>
          <button class="pp-btn pp-unlock">Unlock name</button>
          <button class="pp-btn pp-remove">Remove</button>
        </span>
      </div>
    `);
    row.querySelector('.pp-dl').onclick = () => downloadSharedFile(s);
    row.querySelector('.pp-unlock').onclick = () => unlockSharedName(s);
    row.querySelector('.pp-remove').onclick = () => removeSharedFile(s);
    out.appendChild(row);
  }
}

function escapeHtml(s){ return String(s).replace(/[&<>"']/g,c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c])); }

// ---- Boot ----
function wireButtons(){
  el('#pp-btn-new-folder')?.addEventListener('click', createFolder);
  el('#pp-btn-up')?.addEventListener('click', goUp);

  const picker = el('#pp-file-picker');
  el('#pp-btn-upload')?.addEventListener('click', () => {
    if (!picker) return alert('Missing #pp-file-picker element');
    picker.value = '';
    picker.click();
  });
  picker?.addEventListener('change', async () => {
    try {
      const files = Array.from(picker.files || []);
      for (const file of files) await uploadOne(file);
      await refresh();
    } catch (e) {
      console.error(e); alert('Upload error: ' + e.message);
    }
  });
}

document.addEventListener('DOMContentLoaded', async () => {
  wireButtons();
  await refresh();
});

async function deleteFile(f) {
  try {
    const nameMaybe = (await vaultGetFileKey(f.oid))
      ? await decryptName(await vaultGetFileKey(f.oid), b64dToU8(f.name_iv), b64dToU8(f.enc_name))
      : '[encrypted]';
    const ok = confirm(`Delete "${nameMaybe}"?\n\nThis will overwrite the stored ciphertext with random bytes and then delete the file. This cannot be undone.`);
    if (!ok) return;

    await postJson('/api/file/delete', { file_oid: f.oid });
    log(`Deleted ${f.oid}`);
    await refresh();
  } catch (e) {
    console.error(e);
    alert('Delete failed: ' + e.message);
  }
}

async function removeSharedFile(s) {
  try {
    if (!confirm('Remove this shared file from your view? (Owner copy stays intact)')) return;
    await postJson('/api/share/remove', { file_oid: s.file_oid });
    // Also drop any local key material to be safe:
    if (typeof vaultDelFileKey === 'function') await vaultDelFileKey(s.file_oid);
    await refresh();
  } catch (e) {
    console.error(e);
    alert('Remove failed: ' + e.message);
  }
}
async function deleteDirectory(d) {
  try {
    const ok = confirm(`Delete the folder "${d.name}" and ALL of its contents?\n\nAll contained files will be shredded (ciphertext overwritten) and then deleted.`);
    if (!ok) return;
    await postJson('/api/dir/delete', { dir_oid: d.oid });
    await refresh();
  } catch (e) {
    console.error(e);
    alert('Delete folder failed: ' + e.message);
  }
}
