const crypto = require('crypto');
const a = crypto.createHash('sha256').update('616263', 'hex').digest('hex');
const b = crypto.createHash('sha256').update('abc').digest('hex');
console.log(a === b);
