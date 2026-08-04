const qs = require('querystring');
console.log(qs.escape('a b&c=d/e'));
console.log(qs.escape('plain-safe_chars.ok'));
