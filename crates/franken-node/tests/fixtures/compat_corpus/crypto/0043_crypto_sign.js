const crypto = require('crypto');
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const sig = crypto.sign(null, Buffer.from('msg'), privateKey);
console.log(sig.length);
console.log(crypto.verify(null, Buffer.from('msg'), publicKey, sig));
console.log(crypto.verify(null, Buffer.from('other'), publicKey, sig));
