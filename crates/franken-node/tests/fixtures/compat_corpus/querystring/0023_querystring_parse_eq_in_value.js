const qs = require('querystring');
console.log(JSON.stringify(qs.parse('a=1=2=3&b==&token=abc==')));
