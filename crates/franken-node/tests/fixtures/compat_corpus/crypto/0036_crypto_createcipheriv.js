const crypto = require('crypto');
const key = Buffer.alloc(16, 3), iv = Buffer.alloc(16, 4);
const c = crypto.createCipheriv('aes-128-ctr', key, iv);
const ct = Buffer.concat([c.update('stream mode', 'utf8'), c.final()]);
console.log(ct.toString('hex'));
console.log(ct.length);
const d = crypto.createDecipheriv('aes-128-ctr', key, iv);
console.log(Buffer.concat([d.update(ct), d.final()]).toString('utf8'));
