const qs = require('querystring');
console.log(qs.stringify({ 'k&1': 'v=2/3?4#5', 'p%q': '100%' }));
