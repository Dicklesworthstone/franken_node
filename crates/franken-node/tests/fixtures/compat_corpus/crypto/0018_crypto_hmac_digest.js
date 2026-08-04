const crypto = require('crypto');
console.log(crypto.createHmac('sha256', 'abc').update('xyz').digest('base64'));
