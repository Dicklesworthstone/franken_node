const qs = require('querystring');
const parsed = qs.parse('hasOwnProperty=yes&valueOf=no&toString=str&constructor=ctor');
console.log(parsed.hasOwnProperty, parsed.valueOf, parsed.toString, parsed.constructor);
console.log(JSON.stringify(Object.keys(parsed).sort()));
