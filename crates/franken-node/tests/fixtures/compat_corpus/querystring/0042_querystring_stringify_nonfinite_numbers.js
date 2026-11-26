const qs = require('querystring');
console.log(qs.stringify({ a: NaN, b: Infinity, c: -Infinity, d: 7 }));
