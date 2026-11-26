const crypto = require('crypto');
const k16 = crypto.pbkdf2Sync('passphrase', 'salty', 100, 16, 'sha512');
const k32 = crypto.pbkdf2Sync('passphrase', 'salty', 100, 32, 'sha512');
const k64 = crypto.pbkdf2Sync('passphrase', 'salty', 100, 64, 'sha512');
console.log(k16.length, k32.length, k64.length);
console.log(k64.subarray(0, 16).equals(k16));
console.log(k64.subarray(0, 32).equals(k32));
console.log(k32.toString('hex'));
