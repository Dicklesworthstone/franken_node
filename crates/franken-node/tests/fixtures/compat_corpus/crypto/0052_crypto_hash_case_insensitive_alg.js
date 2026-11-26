const crypto = require('crypto');
const pairs = [['md5', 'MD5'], ['sha1', 'SHA1'], ['sha256', 'SHA256'], ['sha512', 'SHA512']];
for (const [lo, hi] of pairs) {
  const a = crypto.createHash(lo).update('case-check').digest('hex');
  const b = crypto.createHash(hi).update('case-check').digest('hex');
  console.log(lo + ':' + (a === b));
}
