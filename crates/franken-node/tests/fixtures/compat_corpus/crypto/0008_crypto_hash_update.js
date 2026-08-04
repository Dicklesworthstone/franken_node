const crypto = require('crypto');
const a = crypto.createHash('sha256').update(Buffer.from('data')).digest('hex');
const b = crypto.createHash('sha256').update('data', 'utf8').digest('hex');
console.log(a === b);
console.log(a);
