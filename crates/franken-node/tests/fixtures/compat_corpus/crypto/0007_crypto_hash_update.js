const crypto = require('crypto');
const a = crypto.createHash('sha256').update('hello ').update('world').digest('hex');
const b = crypto.createHash('sha256').update('hello world').digest('hex');
console.log(a === b);
console.log(a);
