const qs = require('querystring');
const o = qs.parse('a=&b=&c=3');
console.log(JSON.stringify(o.a), JSON.stringify(o.b), o.c);
