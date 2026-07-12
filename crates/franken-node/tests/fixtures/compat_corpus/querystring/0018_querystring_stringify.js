const qs = require('querystring');
console.log(qs.stringify({ a: { nested: 1 }, b: 'ok' }));
console.log(qs.stringify({ c: null }));
