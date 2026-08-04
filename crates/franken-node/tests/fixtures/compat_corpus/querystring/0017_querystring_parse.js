const qs = require('querystring');
const s = qs.stringify({ a: 'x y', b: ['1', '2'] });
console.log(s);
const o = qs.parse(s);
console.log(o.a, Array.isArray(o.b), o.b.join(','));
