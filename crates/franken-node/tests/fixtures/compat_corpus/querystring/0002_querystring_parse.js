const qs = require('querystring');
const o = qs.parse('a=1&a=2&a=3&b=solo');
console.log(Array.isArray(o.a), o.a.join(','), Array.isArray(o.b), o.b);
