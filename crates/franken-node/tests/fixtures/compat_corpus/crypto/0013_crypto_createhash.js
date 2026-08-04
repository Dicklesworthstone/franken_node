const crypto = require('crypto');
const big = 'abcdefghij'.repeat(1024);
console.log(big.length);
console.log(crypto.createHash('sha256').update(big).digest('hex'));
