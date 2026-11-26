const qs = require('querystring');
const input = { mode: 'a&b=c', ids: ['10', '20', '30'], note: 'hello world' };
const encoded = qs.stringify(input, ';', ':');
const decoded = qs.parse(encoded, ';', ':');
console.log(encoded);
console.log(JSON.stringify(decoded));
