const qs = require('querystring');
const parsed = qs.parse('msg=%F0%9F%9A%80+%E6%97%A5%E6%9C%AC%E8%AA%9E&caf%C3%A9=ok');
console.log(JSON.stringify(parsed));
