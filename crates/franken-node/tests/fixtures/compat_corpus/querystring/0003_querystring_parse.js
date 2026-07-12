const qs = require('querystring');
const o = qs.parse('w:x;y:z', ';', ':');
console.log(Object.keys(o).sort().map(k => k + '=' + o[k]).join('&'));
