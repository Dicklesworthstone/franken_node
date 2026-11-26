const crypto = require('crypto');
const pass = Buffer.from('async-pass');
const salt = Buffer.from('async-salt');
const syncKey = crypto.pbkdf2Sync(pass, salt, 50, 32, 'sha512').toString('hex');
crypto.pbkdf2(pass, salt, 50, 32, 'sha512', (err, asyncKey) => {
  console.log(err === null);
  console.log(Buffer.isBuffer(asyncKey), asyncKey.length);
  console.log(asyncKey.toString('hex') === syncKey);
  console.log(asyncKey.toString('hex'));
});
