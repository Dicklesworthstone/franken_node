const crypto = require('crypto');
const n = crypto.randomInt(10);
console.log(Number.isInteger(n));
console.log(n >= 0 && n < 10);
