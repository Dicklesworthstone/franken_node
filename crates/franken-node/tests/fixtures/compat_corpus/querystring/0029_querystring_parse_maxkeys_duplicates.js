const qs = require('querystring');
const parsed = qs.parse('a=1&a=2&b=3&c=4', '&', '=', { maxKeys: 3 });
console.log(JSON.stringify(parsed));
