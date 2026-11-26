const crypto = require('crypto');
const key = Buffer.alloc(32, 0x33);
const iv = Buffer.alloc(16, 0x44);
const c = crypto.createCipheriv('aes-256-cbc', key, iv);
const ct = Buffer.concat([c.update(Buffer.alloc(0)), c.final()]);
const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
const pt = Buffer.concat([d.update(ct), d.final()]);
console.log(ct.length, pt.length);
console.log(ct.toString('hex'));
