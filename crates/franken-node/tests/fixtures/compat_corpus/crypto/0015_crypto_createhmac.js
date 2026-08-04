const crypto = require('crypto');
const d = crypto.createHmac('sha1', 'secret').update('message').digest('hex');
console.log(d);
console.log(d.length);
