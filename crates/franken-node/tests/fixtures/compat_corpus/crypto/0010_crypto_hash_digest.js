const crypto = require('crypto');
const d = crypto.createHash('sha256').update('x').digest();
console.log(Buffer.isBuffer(d));
console.log(d.length);
console.log(d.toString('hex'));
