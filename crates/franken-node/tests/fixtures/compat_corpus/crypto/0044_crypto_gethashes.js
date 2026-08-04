const crypto = require('crypto');
const hs = crypto.getHashes();
console.log(Array.isArray(hs));
console.log(hs.includes('sha256'));
console.log(hs.includes('sha512'));
