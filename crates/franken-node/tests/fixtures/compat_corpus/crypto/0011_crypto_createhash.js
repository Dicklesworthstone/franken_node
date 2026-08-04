const crypto = require('crypto');
console.log(crypto.createHash('sha256').digest('hex'));
console.log(crypto.createHash('sha1').digest('hex'));
