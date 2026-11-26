const crypto = require('crypto');
function threw(fn) {
  try { fn(); return false; } catch (e) { return e instanceof Error; }
}
const badKey = threw(() => crypto.createCipheriv('aes-256-cbc', Buffer.alloc(16), Buffer.alloc(16)));
const badIv = threw(() => crypto.createCipheriv('aes-256-cbc', Buffer.alloc(32), Buffer.alloc(8)));
const badAlg = threw(() => crypto.createCipheriv('aes-999-unknown', Buffer.alloc(32), Buffer.alloc(16)));
console.log(badKey, badIv, badAlg);
