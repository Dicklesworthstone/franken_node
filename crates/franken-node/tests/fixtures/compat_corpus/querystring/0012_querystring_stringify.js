const qs = require('querystring');
console.log(qs.stringify({ a: '1', b: '2' }, ';', ':'));
