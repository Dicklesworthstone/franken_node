const crypto = require('crypto');
try {
  crypto.randomInt(5, 5);
  console.log('no-throw');
} catch (e) {
  console.log(e instanceof RangeError);
  console.log(String(e.code));
}
