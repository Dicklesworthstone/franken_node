const crypto = require('crypto');
const dMd5 = crypto.createHash('md5').update('payload').digest();
const dSha1 = crypto.createHash('sha1').update('payload').digest();
const dSha512 = crypto.createHash('sha512').update('payload').digest();
console.log(Buffer.isBuffer(dMd5), dMd5.length);
console.log(Buffer.isBuffer(dSha1), dSha1.length);
console.log(Buffer.isBuffer(dSha512), dSha512.length);
console.log(dMd5.toString('hex'));
