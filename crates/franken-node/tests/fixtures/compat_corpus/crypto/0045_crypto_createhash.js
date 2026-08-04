const crypto = require('crypto');
try {
  crypto.createHash('not-a-real-hash');
  console.log('no-throw');
} catch (e) {
  console.log(e instanceof Error);
  console.log(typeof e.message === 'string');
}
