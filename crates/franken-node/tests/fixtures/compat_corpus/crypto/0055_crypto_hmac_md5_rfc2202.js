const crypto = require('crypto');
const v1 = crypto.createHmac('md5', Buffer.alloc(16, 0x0b))
  .update('Hi There')
  .digest('hex');
const v2 = crypto.createHmac('md5', 'Jefe')
  .update('what do ya want for nothing?')
  .digest('hex');
console.log(v1);
console.log(v2);
