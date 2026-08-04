const crypto = require('crypto');
console.log(typeof crypto.constants === 'object');
console.log(crypto.constants.RSA_PKCS1_PADDING === 1);
