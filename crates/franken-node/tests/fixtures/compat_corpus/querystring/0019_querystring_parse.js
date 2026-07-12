const qs = require('querystring');
const o = qs.parse('');
console.log(Object.keys(o).length, typeof o);
