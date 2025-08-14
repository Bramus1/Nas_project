// assets/js/pp/storage-upload.js
import { postJson, getJson } from './api.js';
import { genFileKey, encryptName, encryptChunk, b64e, b64eIV,hashU8, merkleRoot      } from './crypto/filecrypto.js';
import { ensureIdentity, signBytesECDSA } from './crypto/keys';
const CHUNK = 64 * 1024; // 64 KiB

function log(msg) {
  const el = document.getElementById('pp-upload-log');
  if (el) el.textContent += msg + '\n';
  console.log('[PP-UP]', msg);
}

async function ensureFolder(aesKey, name) {
  if (!name) return null; // root
  const { iv, ciphertext } = await encryptName(aesKey, name);
  const r = await postJson('/api/dir/create', {
    parent_oid: null,
    enc_name: b64e(ciphertext),
    name_iv: b64eIV(iv),
  });
  return r.oid;
}

async function uploadFile(file) {
  // 1) One AES key per file
  const fkey = await genFileKey();

  // 2) Encrypt filename
  const enc = await encryptName(fkey, file.name);

  // 3) Optional: create folder if requested (encrypted name too)
  const folderName = document.getElementById('pp-folder')?.value?.trim() || '';
  const dirOid = await ensureFolder(fkey, folderName);

  // 4) init file on server
  const init = await postJson('/api/file/init', {
    directory_oid: dirOid,
    enc_name: b64e(enc.ciphertext),
    name_iv: b64eIV(enc.iv),
    size_bytes: file.size,
  });
  const { file_oid, upload_token } = init;
  log(`file_oid=${file_oid}`);

  // 5) Read + encrypt + send chunks
  let sent = 0;
  let index = 0;
  const totalChunks = Math.ceil(file.size / CHUNK);
  const leafHashes = [];
  while (sent < file.size) {
    const end = Math.min(file.size, sent + CHUNK);
    const blob = file.slice(sent, end);
    const buf = new Uint8Array(await blob.arrayBuffer());
    const aadCtx = { fileOid: file_oid, index, total: totalChunks, version: 1 };

     const { iv, ciphertext } = await encryptChunk(fkey, buf, aadCtx);
      // A2: hash the ciphertext for the Merkle leaves
    leafHashes.push(await hashU8(ciphertext));
    await postJson('/api/file/chunk', {
      file_oid, upload_token, index,
      iv: b64eIV(iv),
      ciphertext: b64e(ciphertext),
      length: buf.length,
    });
    sent += buf.length;
    index += 1;
    if (index % 32 === 0) log(`sent ${sent}/${file.size}`);
  }

   //finalize (A2: compute Merkle root and include a manifest)
const root = await merkleRoot(leafHashes);
const manifest = {
  algo: 'sha256',
  n: totalChunks,
  root_b64: b64e(root),
  version: 1,
};

  // --- Non-repudiation: sign manifest with ECDSA (P-256) ---
  try {
    const { ecdsa } = await ensureIdentity();
    const enc = new TextEncoder();
    const toSign = enc.encode(`pp:manifest|${file_oid}|sha256|${totalChunks}|${b64e(root)}|v1`);
    const sig = await signBytesECDSA(ecdsa.privateKey, toSign);
    manifest.sig_b64 = b64e(sig);
  } catch (e) {
    console.warn('Manifest signature skipped:', e);
  }

  // 6) finalize
  await postJson('/api/file/finalize', { file_oid, upload_token, chunk_count: totalChunks, manifest });
  log(`File ${file.name} (${file.size} bytes) uploaded successfully.`);
//  log('Upload complete.');
}

document.getElementById('pp-upload-btn')?.addEventListener('click', async () => {
  const f = document.getElementById('pp-file')?.files?.[0];
  if (!f) return alert('Choose a file first');
  try {
    await uploadFile(f);
  } catch (e) {
    console.error(e);
    alert('Upload failed: ' + e.message);
  }
});

function wireButtons(){
  const picker = document.querySelector('#pp-file-picker');

  document.querySelector('#pp-btn-new-folder')?.addEventListener('click', createFolder);
  document.querySelector('#pp-btn-up')?.addEventListener('click', goUp);

  document.querySelector('#pp-btn-upload')?.addEventListener('click', () => {
    if (!picker) { alert('Missing #pp-file-picker element'); return; }
    picker.value = "";   // reset so change fires even if same files chosen
    picker.click();      // open the OS file dialog
  });

  picker?.addEventListener('change', async () => {
    try {
      const files = Array.from(picker.files || []);
      for (const f of files) await uploadOne(f);
      await refresh();
    } catch (e) {
      console.error(e);
      alert('Upload error: ' + e.message);
    }
  });
}

document.addEventListener('DOMContentLoaded', async () => {
  wireButtons();
  await refresh();
});

