const crypto = require('crypto');
console.log(crypto.createHash('sha1').update('The quick brown fox jumps over the lazy dog').digest('hex'));
