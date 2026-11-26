const crypto = require('crypto');
const key = Buffer.alloc(32, 0x5e);
const iv = Buffer.alloc(12, 0x6f);
const enc = crypto.createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([enc.update('authenticated-secret', 'utf8'), enc.final()]);
const tag = enc.getAuthTag();

const badCt = Buffer.from(ct);
badCt[0] ^= 0x01;
let ctThrew = false;
try {
  const d1 = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d1.setAuthTag(tag);
  Buffer.concat([d1.update(badCt), d1.final()]);
} catch (e) {
  ctThrew = e instanceof Error;
}

const badTag = Buffer.from(tag);
badTag[badTag.length - 1] ^= 0x80;
let tagThrew = false;
try {
  const d2 = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d2.setAuthTag(badTag);
  Buffer.concat([d2.update(ct), d2.final()]);
} catch (e) {
  tagThrew = e instanceof Error;
}

console.log(ctThrew, tagThrew);
