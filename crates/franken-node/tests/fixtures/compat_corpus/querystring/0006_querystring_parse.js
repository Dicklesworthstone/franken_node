const qs = require('querystring');
const o = qs.parse('flag&other');
console.log(Object.keys(o).sort().join(','), JSON.stringify(o.flag), JSON.stringify(o.other));
