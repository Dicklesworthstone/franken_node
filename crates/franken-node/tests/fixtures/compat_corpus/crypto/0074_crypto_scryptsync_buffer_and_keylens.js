const crypto = require('crypto');
const k16 = crypto.scryptSync(Buffer.from('pw'), Buffer.from('naCl'), 16, { N: 1024, r: 8, p: 1 });
const k64 = crypto.scryptSync(Buffer.from('pw'), Buffer.from('naCl'), 64, { N: 1024, r: 8, p: 1 });
console.log(Buffer.isBuffer(k16), k16.length);
console.log(Buffer.isBuffer(k64), k64.length);
console.log(k64.subarray(0, 16).equals(k16));
console.log(k16.toString('hex'));
