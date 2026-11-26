const qs = require('querystring');
const parts = [];
for (let i = 0; i < 12; i++) parts.push('k' + i + '=' + i);
const parsed = qs.parse(parts.join('&'), null, null, { maxKeys: 0 });
console.log(Object.keys(parsed).length, parsed.k0, parsed.k11);
