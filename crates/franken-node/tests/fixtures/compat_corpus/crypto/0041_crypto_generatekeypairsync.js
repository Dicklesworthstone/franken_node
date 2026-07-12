const crypto = require('crypto');
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
console.log(publicKey.type);
console.log(privateKey.type);
console.log(publicKey.asymmetricKeyType);
console.log(privateKey.asymmetricKeyType);
