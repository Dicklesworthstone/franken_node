const crypto = require('crypto');
const u = crypto.randomUUID();
console.log(typeof u);
console.log(u.length);
console.log(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(u));
