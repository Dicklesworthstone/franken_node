const qs = require('querystring');
console.log(qs.unescape('a%20b%26c'), qs.unescape('%E4%B8%AD'));
console.log(qs.unescape('x+y'));
