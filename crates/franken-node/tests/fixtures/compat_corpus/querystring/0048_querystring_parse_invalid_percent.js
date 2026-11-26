const qs = require('querystring');
console.log(JSON.stringify(qs.parse('a=%ZZ&b=%E0%A4%A&c=100%&d=%2')));
