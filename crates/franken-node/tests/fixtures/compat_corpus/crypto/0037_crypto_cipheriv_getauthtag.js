const crypto = require('crypto');
const key = Buffer.alloc(32, 5), iv = Buffer.alloc(12, 6);
const c = crypto.createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([c.update('gcm data', 'utf8'), c.final()]);
const tag = c.getAuthTag();
console.log(ct.toString('hex'));
console.log(tag.toString('hex'));
console.log(tag.length);
