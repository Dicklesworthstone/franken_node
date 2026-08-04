const crypto = require('crypto');
const k = crypto.scryptSync('password', 'salt', 24);
console.log(k.toString('hex'));
console.log(k.length);
