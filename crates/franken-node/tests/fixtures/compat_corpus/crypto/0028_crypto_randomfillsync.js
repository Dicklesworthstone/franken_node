const crypto = require('crypto');
const b = Buffer.alloc(8);
const r = crypto.randomFillSync(b);
console.log(r === b);
console.log(r.length);
