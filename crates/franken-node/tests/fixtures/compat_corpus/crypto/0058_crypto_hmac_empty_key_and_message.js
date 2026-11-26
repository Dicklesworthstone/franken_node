const crypto = require('crypto');
console.log(crypto.createHmac('sha256', '').update('').digest('hex'));
console.log(crypto.createHmac('sha256', 'secret').update('').digest('hex'));
console.log(crypto.createHmac('sha1', '').update('msg').digest('hex'));
