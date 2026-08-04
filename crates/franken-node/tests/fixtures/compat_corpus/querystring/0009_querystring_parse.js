const qs = require('querystring');
const o = qs.parse('a[b]=1&a[c]=2');
console.log(Object.keys(o).sort().join('|'), o['a[b]'], o['a[c]'], typeof o.a);
