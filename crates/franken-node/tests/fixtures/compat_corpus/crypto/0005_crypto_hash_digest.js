const crypto = require('crypto');
console.log(crypto.createHash('sha256').update('hello').digest('base64'));
console.log(crypto.createHash('sha256').update('hello').digest('base64url'));
