const qs = require('querystring');
console.log(JSON.stringify(qs.parse('=val&a=1&=val2')));
console.log(JSON.stringify(qs.parse('=')));
