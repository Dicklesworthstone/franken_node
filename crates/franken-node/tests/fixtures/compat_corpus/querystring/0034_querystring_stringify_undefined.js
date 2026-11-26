const qs = require('querystring');
console.log(qs.stringify({ a: 'x', b: undefined, c: 'y' }));
console.log(qs.stringify({ only: undefined }));
