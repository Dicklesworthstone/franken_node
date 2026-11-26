const qs = require('querystring');
const parsed = qs.parse('first%20name=John%20Doe&a%26b=c%3Dd&k+1=v+1');
console.log(JSON.stringify(parsed));
