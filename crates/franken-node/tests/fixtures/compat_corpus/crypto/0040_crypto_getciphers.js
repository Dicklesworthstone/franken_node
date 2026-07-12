const crypto = require('crypto');
const cs = crypto.getCiphers();
console.log(Array.isArray(cs));
console.log(cs.includes('aes-256-cbc'));
console.log(cs.includes('aes-128-ctr'));
