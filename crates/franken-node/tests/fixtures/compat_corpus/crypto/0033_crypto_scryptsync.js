const crypto = require('crypto');
console.log(crypto.scryptSync('pw', 'na', 16, { N: 1024, r: 8, p: 1 }).toString('hex'));
