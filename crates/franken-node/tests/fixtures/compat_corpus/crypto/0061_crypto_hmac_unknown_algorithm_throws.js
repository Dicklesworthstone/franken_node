const crypto = require('crypto');
try {
  crypto.createHmac('not-a-real-hmac-alg', 'key');
  console.log('no-throw');
} catch (e) {
  console.log(e instanceof Error);
  console.log(typeof e.message === 'string' && e.message.length > 0);
}
