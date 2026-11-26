const qs = require('querystring');
console.log(JSON.stringify(qs.parse(null)));
console.log(JSON.stringify(qs.parse(undefined)));
console.log(JSON.stringify(qs.stringify(null)));
console.log(JSON.stringify(qs.stringify(undefined)));
console.log(JSON.stringify(qs.stringify('abc')));
console.log(JSON.stringify(qs.stringify(42)));
