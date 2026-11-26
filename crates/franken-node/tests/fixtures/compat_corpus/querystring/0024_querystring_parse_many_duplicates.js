const qs = require('querystring');
const parsed = qs.parse('tag=alpha&tag=beta&tag=gamma&tag=delta');
console.log(Array.isArray(parsed.tag), parsed.tag.length);
console.log(JSON.stringify(parsed));
