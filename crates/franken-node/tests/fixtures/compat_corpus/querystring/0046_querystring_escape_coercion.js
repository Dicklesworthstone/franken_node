const qs = require('querystring');
console.log(qs.escape(true));
console.log(qs.escape(false));
console.log(qs.escape(42));
console.log(qs.escape(null));
console.log(qs.escape(undefined));
