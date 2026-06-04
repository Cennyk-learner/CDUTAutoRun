// 【安全声明】微信小程序包(.wxapkg)解密/解包脚本，仅用于安全研究与学习交流，
// 不得用于侵犯他人知识产权或任何非法用途；后果与作者本人无关。详见 安全声明.md。
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function decryptWxapkg(buf, appid) {
  if (buf.slice(0,6).toString() !== 'V1MMWX') return buf;
  const key = crypto.pbkdf2Sync(Buffer.from(appid), Buffer.from('saltiest'), 1000, 32, 'sha1');
  const iv = Buffer.from('the iv: 16 bytes');
  const firstLen = Math.min(1024, buf.length - 6);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  // keep PKCS#7 auto padding enabled: encrypted segment is 1023 bytes plaintext + 1 byte padding
  const first = Buffer.concat([decipher.update(buf.slice(6, 6 + firstLen)), decipher.final()]);
  const rest = Buffer.from(buf.slice(6 + firstLen));
  const xorKey = appid && appid.length >= 2 ? appid.charCodeAt(appid.length - 2) : 0x66;
  for (let i=0; i<rest.length; i++) rest[i] ^= xorKey;
  return Buffer.concat([first, rest]);
}

function u32be(buf, off) { return buf.readUInt32BE(off); }
function safeName(name) {
  name = name.replace(/^\/+/, '').replace(/\\/g, '/');
  const parts = [];
  for (const p of name.split('/')) {
    if (!p || p === '.' || p === '..') continue;
    parts.push(p);
  }
  return parts.join(path.sep) || '_root_';
}

function unpack(pkg, outDir, appid) {
  const enc = fs.readFileSync(pkg);
  const buf = decryptWxapkg(enc, appid);
  if (buf[0] !== 0xbe || buf[13] !== 0xed) {
    throw new Error(`bad magic after decrypt: ${buf.slice(0,16).toString('hex')}`);
  }
  const indexLen = u32be(buf, 5);
  const bodyLen = u32be(buf, 9);
  const fileCount = u32be(buf, 14);
  let off = 18;
  fs.mkdirSync(outDir, {recursive:true});
  const entries = [];
  for (let i=0; i<fileCount; i++) {
    const nameLen = u32be(buf, off); off += 4;
    const name = buf.slice(off, off + nameLen).toString('utf8'); off += nameLen;
    const foff = u32be(buf, off); off += 4;
    const flen = u32be(buf, off); off += 4;
    entries.push({name, foff, flen});
  }
  const manifest = {pkg, appid, indexLen, bodyLen, fileCount, entries};
  fs.writeFileSync(path.join(outDir, '_manifest.json'), JSON.stringify(manifest, null, 2));
  for (const e of entries) {
    const rel = safeName(e.name);
    const dst = path.join(outDir, rel);
    fs.mkdirSync(path.dirname(dst), {recursive:true});
    fs.writeFileSync(dst, buf.slice(e.foff, e.foff + e.flen));
  }
  console.log(`[OK] ${pkg}`);
  console.log(`     appid=${appid} files=${fileCount} indexLen=${indexLen} bodyLen=${bodyLen}`);
  console.log(`     out=${outDir}`);
  console.log(`     first entries: ${entries.slice(0,8).map(e=>e.name).join(', ')}`);
}

if (process.argv.length < 5) {
  console.error('usage: node ctf_wxapkg_unpack.js <appid> <outBase> <pkg...>');
  process.exit(2);
}
const appid = process.argv[2];
const outBase = process.argv[3];
for (const pkg of process.argv.slice(4)) {
  const version = path.basename(path.dirname(pkg));
  const base = path.basename(pkg, '.wxapkg').replace(/[^a-zA-Z0-9_.-]/g, '_');
  unpack(pkg, path.join(outBase, appid, version, base), appid);
}

