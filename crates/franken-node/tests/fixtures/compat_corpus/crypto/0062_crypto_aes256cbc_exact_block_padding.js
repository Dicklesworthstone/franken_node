const crypto = require('crypto');
const key = Buffer.alloc(32, 0x11);
const iv = Buffer.alloc(16, 0x22);
const pt = Buffer.from('0123456789abcdef', 'utf8'); // exact 16-byte AES block
const c = crypto.createCipheriv('aes-256-cbc', key, iv);
const ct = Buffer.concat([c.update(pt), c.final()]);
const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
const out = Buffer.concat([d.update(ct), d.final()]);
console.log(pt.length, ct.length);
console.log(ct.toString('hex'));
console.log(out.equals(pt), out.toString('utf8'));
