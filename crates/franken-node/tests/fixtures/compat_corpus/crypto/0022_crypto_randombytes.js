const crypto = require('crypto');
const b = crypto.randomBytes(16);
console.log(Buffer.isBuffer(b));
console.log(b.length);
console.log(crypto.randomBytes(0).length);
