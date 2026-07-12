const crypto = require('crypto');
const h = crypto.createHash('sha256').update('foo').update('bar').update('baz');
console.log(h.digest('hex'));
