const crypto = require('crypto');
try {
  crypto.timingSafeEqual(Buffer.from('ab'), Buffer.from('abc'));
  console.log('no-throw');
} catch (e) {
  console.log(e instanceof RangeError);
  console.log(String(e.code));
}
