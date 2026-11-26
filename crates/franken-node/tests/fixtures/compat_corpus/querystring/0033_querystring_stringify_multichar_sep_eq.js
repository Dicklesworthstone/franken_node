const qs = require('querystring');
console.log(qs.stringify({ a: ['1', '3'], b: '2' }, '||', ':='));
console.log(qs.stringify({ x: 'hello', y: 'world' }, '::', '--'));
