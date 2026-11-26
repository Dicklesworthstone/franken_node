const crypto = require('crypto');
const v1 = crypto.pbkdf2Sync('password', 'salt', 1, 20, 'sha1').toString('hex');
const v2 = crypto.pbkdf2Sync('password', 'salt', 2, 20, 'sha1').toString('hex');
const vBuf = crypto.pbkdf2Sync(Buffer.from('password'), Buffer.from('salt'), 2, 20, 'sha1').toString('hex');
console.log(v1 === '0c60c80f961f0e71f3a9b524af6012062fe037a6', v1);
console.log(v2 === 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957', v2);
console.log(v2 === vBuf);
