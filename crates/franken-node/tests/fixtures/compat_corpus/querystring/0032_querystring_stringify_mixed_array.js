const qs = require('querystring');
console.log(qs.stringify({ items: [1, true, false, 'hi', null, undefined] }));
