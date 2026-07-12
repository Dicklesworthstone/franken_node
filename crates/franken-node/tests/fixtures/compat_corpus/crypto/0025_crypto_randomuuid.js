const crypto = require('crypto');
const u = crypto.randomUUID();
console.log(u[14] === '4');
console.log(['8', '9', 'a', 'b'].includes(u[19]));
