const crypto = require('crypto');
for (const alg of ['md5', 'sha1', 'sha256', 'sha512']) {
  console.log(alg + ':' + crypto.createHash(alg).update('abc').digest('hex'));
}
