const crypto = require('crypto');
const buf = crypto.createHmac('sha256', 'key-1').update('data-1').digest();
const b64url = crypto.createHmac('sha256', 'key-1').update('data-1').digest('base64url');
console.log(Buffer.isBuffer(buf), buf.length);
console.log(b64url.includes('+') || b64url.includes('/') || b64url.includes('='));
console.log(buf.toString('base64url') === b64url);
console.log(b64url);
