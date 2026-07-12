const qs = require('querystring');
const o = qs.parse('a=1&b=2&c=3&d=4', null, null, { maxKeys: 2 });
console.log(Object.keys(o).sort().join(','), Object.keys(o).length);
