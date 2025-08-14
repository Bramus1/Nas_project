// assets/js/pp/chat-fs.js
import { ensureIdentity } from './crypto/keys.js';
import { getJson } from './api.js';

const te = new TextEncoder();
function b64e(u8){return btoa(String.fromCharCode(...u8)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
function b64d(s){s=s.replace(/-/g,'+').replace(/_/g,'/');return new Uint8Array([...atob(s)].map(c=>c.charCodeAt(0)));}

async function hkdfRaw(ikm, infoStr, len=32, salt=new Uint8Array(32)){
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name:'HKDF', hash:'SHA-256', salt, info: te.encode(infoStr) }, base, len*8));
}

const SESS = new Map(); // peer -> { eph, peerEph, sendCK, recvCK, ready }

async function makeEphemeral(){
  return crypto.subtle.generateKey({ name:'ECDH', namedCurve:'P-256' }, false, ['deriveBits','deriveKey']);
}
async function signEphemeral(jwk){
  const { ecdsa } = await ensureIdentity();
  const msg = te.encode(JSON.stringify(jwk));
  const sig = await crypto.subtle.sign({ name:'ECDSA', hash:'SHA-256' }, ecdsa.privateKey, msg);
  return new Uint8Array(sig);
}
async function verifyPeerEphemeral(peer, ephJwk, sigB64){
  const ks = await getJson(`/api/keys/of/${encodeURIComponent(peer)}`);
  if (!ks?.ecdsa) throw new Error('peer ECDSA pubkey missing');
  const pub = await crypto.subtle.importKey('jwk', ks.ecdsa, { name:'ECDSA', namedCurve:'P-256' }, true, ['verify']);
  const ok = await crypto.subtle.verify({ name:'ECDSA', hash:'SHA-256' }, pub, b64d(sigB64), te.encode(JSON.stringify(ephJwk)));
  if(!ok) throw new Error('ephemeral signature invalid');
}
async function deriveSession(myEphPriv, peerEphJwk, me, peer){
  const peerPub = await crypto.subtle.importKey('jwk', peerEphJwk, { name:'ECDH', namedCurve:'P-256' }, false, []);
  const bits = await crypto.subtle.deriveBits({ name:'ECDH', public: peerPub }, myEphPriv, 256);
  const ctx = `pp-chat-fs-v1|me:${me}|peer:${peer}|peerX:${peerEphJwk.x}|peerY:${peerEphJwk.y}`;
  const root   = await hkdfRaw(bits, 'root|'+b64e(te.encode(ctx)), 32);
  const sendCK = await hkdfRaw(root, `ck|send|${me}->${peer}`, 32);
  const recvCK = await hkdfRaw(root, `ck|recv|${peer}->${me}`, 32);
  return { sendCK, recvCK };
}
async function nextMsgKey(ck, dir){
  const mk  = await hkdfRaw(ck, `mk|${dir}`, 32);
  const nck = await hkdfRaw(ck, `ck|next|${dir}`, 32);
  return { mk, nck };
}

export function attachChatFS(socket){
  socket.addEventListener('open', async () => {
    const me   = window.CURRENT_USERNAME || (window.getUserName && getUserName()) || '';
    const peer = (window.getUserName && getUserName()) || '';
    if (!peer) return;
    const eph = await makeEphemeral();
    const jwk = await crypto.subtle.exportKey('jwk', eph.publicKey);
    const sig = await signEphemeral(jwk);
    SESS.set(peer, { eph, ready:false });
    socket.send(JSON.stringify({ type:'ppfs-hello', to: peer, epk: jwk, sig: b64e(sig) }));
  });

  socket.addEventListener('message', async (ev) => {
    try{
      const msg = JSON.parse(ev.data);
      if (msg?.type !== 'ppfs-hello') return;
      const peer = msg.from || (msg.to && window.CURRENT_USERNAME);
      const me   = window.CURRENT_USERNAME || (window.getUserName && getUserName()) || '';
      if (!peer) return;

      await verifyPeerEphemeral(peer, msg.epk, msg.sig);

      let st = SESS.get(peer);
      if (!st){
        const eph = await makeEphemeral();
        st = { eph, ready:false };
        SESS.set(peer, st);
        const jwk = await crypto.subtle.exportKey('jwk', eph.publicKey);
        const sig = await signEphemeral(jwk);
        socket.send(JSON.stringify({ type:'ppfs-hello', to: peer, epk: jwk, sig: b64e(sig) }));
      }
      const { sendCK, recvCK } = await deriveSession(st.eph.privateKey, msg.epk, me, peer);
      st.peerEph = msg.epk; st.sendCK = sendCK; st.recvCK = recvCK; st.ready = true;
      SESS.set(peer, st);
    }catch(e){ console.error('[ppfs] handshake', e); }
  });
}

export async function encryptChatFS(plaintextU8){
  const peer = (window.getUserName && getUserName()) || '';
  const st = SESS.get(peer);
  if (!st?.ready) throw new Error('FS session not ready');
  const { mk, nck } = await nextMsgKey(st.sendCK, `send|${window.CURRENT_USERNAME}->${peer}`);
  st.sendCK = nck;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const k  = await crypto.subtle.importKey('raw', mk, { name:'AES-GCM' }, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name:'AES-GCM', iv }, k, plaintextU8));
  return new Uint8Array([...iv, ...ct]).buffer;
}
export async function decryptChatFS(ivPlusCtBuf){
  const peer = (window.getUserName && getUserName()) || '';
  const st = SESS.get(peer);
  if (!st?.ready) throw new Error('FS session not ready');
  const buf = new Uint8Array(ivPlusCtBuf);
  const iv  = buf.slice(0,12);
  const ct  = buf.slice(12);
  const { mk, nck } = await nextMsgKey(st.recvCK, `recv|${peer}->${window.CURRENT_USERNAME}`);
  st.recvCK = nck;
  const k  = await crypto.subtle.importKey('raw', mk, { name:'AES-GCM' }, false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, k, ct);
  return new Uint8Array(pt);
}
