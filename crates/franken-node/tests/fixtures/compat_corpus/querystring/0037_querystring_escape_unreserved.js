const qs = require('querystring');
console.log(qs.escape("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"));
console.log(JSON.stringify(qs.escape('')));
