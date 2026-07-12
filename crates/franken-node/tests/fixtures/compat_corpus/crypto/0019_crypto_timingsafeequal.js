const crypto = require('crypto');
const a = Buffer.from('0123456789abcdef');
const b = Buffer.from('0123456789abcdef');
console.log(crypto.timingSafeEqual(a, b));
