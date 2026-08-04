const crypto = require('crypto');
const key = Buffer.alloc(32, 7), iv = Buffer.alloc(16, 9);
const c = crypto.createCipheriv('aes-256-cbc', key, iv);
const ct = Buffer.concat([c.update('roundtrip me', 'utf8'), c.final()]);
const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
const pt = Buffer.concat([d.update(ct), d.final()]);
console.log(pt.toString('utf8'));
