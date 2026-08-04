const crypto = require('crypto');
const d = crypto.createHash('sha512').update('abc').digest('hex');
console.log(d);
console.log(d.length);
