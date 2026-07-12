const crypto = require('crypto');
console.log(crypto.createHash('sha256').update('abc').digest('hex'));
