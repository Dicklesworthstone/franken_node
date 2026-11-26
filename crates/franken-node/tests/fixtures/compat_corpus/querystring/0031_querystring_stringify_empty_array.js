const qs = require('querystring');
console.log(JSON.stringify(qs.stringify({ a: [] })));
console.log(JSON.stringify(qs.stringify({ a: [], b: 'ok', c: [] })));
