const crypto = require('crypto');
const key = Buffer.alloc(32, 8), iv = Buffer.alloc(16, 8);
const c1 = crypto.createCipheriv('aes-256-cbc', key, iv);
const a = Buffer.concat([c1.update('hello '), c1.update('world'), c1.final()]);
const c2 = crypto.createCipheriv('aes-256-cbc', key, iv);
const b = Buffer.concat([c2.update('hello world'), c2.final()]);
console.log(a.equals(b));
console.log(a.length);
