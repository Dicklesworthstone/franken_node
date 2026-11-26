const crypto = require('crypto');
console.log(crypto.createHash('md5').update('').digest('hex'));
console.log(crypto.createHash('sha512').update('').digest('hex'));
