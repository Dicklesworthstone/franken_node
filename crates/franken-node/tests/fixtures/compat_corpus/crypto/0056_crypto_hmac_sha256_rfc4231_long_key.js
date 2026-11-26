const crypto = require('crypto');
const longKey = Buffer.alloc(131, 0xaa);
const mac = crypto.createHmac('sha256', longKey)
  .update('Test Using Larger Than Block-Size Key - Hash Key First')
  .digest('hex');
console.log(mac);
console.log(mac === '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54');
