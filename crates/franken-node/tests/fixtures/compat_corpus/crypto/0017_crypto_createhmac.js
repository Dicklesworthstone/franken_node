const crypto = require('crypto');
const a = crypto.createHmac('sha256', Buffer.from('key1')).update('msg').digest('hex');
const b = crypto.createHmac('sha256', 'key1').update('msg').digest('hex');
console.log(a === b);
console.log(a);
