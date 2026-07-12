const crypto = require('crypto');
crypto.pbkdf2('pw', 's', 100, 8, 'sha256', (err, key) => {
  console.log(err === null);
  console.log(key.toString('hex'));
  console.log(key.equals(crypto.pbkdf2Sync('pw', 's', 100, 8, 'sha256')));
});
