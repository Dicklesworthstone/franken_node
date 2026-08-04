const crypto = require('crypto');
const k = crypto.pbkdf2Sync('password', 'salt', 1000, 32, 'sha256');
console.log(k.toString('hex'));
console.log(k.length);
