const qs = require('querystring');
console.log(JSON.stringify(qs.parse('&&a=1&&&b=2&&')));
console.log(JSON.stringify(qs.parse('&&&')));
