const qs = require('querystring');
const o = qs.parse('foo=bar&abc=xyz');
console.log(Object.keys(o).sort().map(k => k + '=' + o[k]).join('&'));
