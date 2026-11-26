const qs = require('querystring');
console.log(qs.unescape('%2520'));
console.log(qs.unescape('a%252Bb'));
console.log(JSON.stringify(qs.unescape('')));
