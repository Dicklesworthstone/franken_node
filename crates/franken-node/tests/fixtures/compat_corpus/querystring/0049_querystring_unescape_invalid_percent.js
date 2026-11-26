const qs = require('querystring');
console.log(qs.unescape('%ZZ+a%20b'));
console.log(qs.unescape('%E0%A4%A'));
console.log(qs.unescape('100%'));
console.log(qs.unescape('%2'));
