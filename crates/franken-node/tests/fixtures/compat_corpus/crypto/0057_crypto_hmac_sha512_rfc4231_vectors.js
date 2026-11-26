const crypto = require('crypto');
const tc1 = crypto.createHmac('sha512', Buffer.alloc(20, 0x0b))
  .update('Hi There')
  .digest('hex');
const tc2 = crypto.createHmac('sha512', 'Jefe')
  .update('what do ya want for nothing?')
  .digest('hex');
console.log(tc1.length, tc1);
console.log(tc2.length, tc2);
