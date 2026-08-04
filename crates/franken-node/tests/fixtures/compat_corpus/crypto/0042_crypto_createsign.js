const crypto = require('crypto');
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const s = crypto.createSign('SHA256').update('signed payload').sign(privateKey);
console.log(Buffer.isBuffer(s));
console.log(crypto.createVerify('SHA256').update('signed payload').verify(publicKey, s));
console.log(crypto.createVerify('SHA256').update('tampered').verify(publicKey, s));
