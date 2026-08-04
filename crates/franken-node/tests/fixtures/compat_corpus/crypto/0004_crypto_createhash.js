const crypto = require('crypto');
console.log(crypto.createHash('md5').update('hello world').digest('hex'));
