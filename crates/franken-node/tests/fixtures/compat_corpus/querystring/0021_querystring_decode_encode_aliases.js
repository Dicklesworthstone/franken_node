const qs = require('querystring');
console.log(qs.decode === qs.parse);
console.log(qs.encode === qs.stringify);
console.log(JSON.stringify(qs.decode('a=1&b=2')));
console.log(qs.encode({ a: '1', b: '2' }));
