const qs = require('querystring');
console.log(JSON.stringify(qs.stringify({})));
console.log(qs.stringify({}).length);
