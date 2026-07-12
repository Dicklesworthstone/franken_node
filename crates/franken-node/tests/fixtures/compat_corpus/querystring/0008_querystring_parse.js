const qs = require('querystring');
const o = qs.parse('a=%E4%B8%AD%E6%96%87&b=x%20y');
console.log(o.a, o.b);
