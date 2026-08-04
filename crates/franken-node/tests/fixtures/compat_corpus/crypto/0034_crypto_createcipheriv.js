const crypto = require('crypto');
const key = Buffer.alloc(32, 1), iv = Buffer.alloc(16, 2);
const c = crypto.createCipheriv('aes-256-cbc', key, iv);
const ct = Buffer.concat([c.update('secret message', 'utf8'), c.final()]);
console.log(ct.toString('hex'));
console.log(ct.length);
