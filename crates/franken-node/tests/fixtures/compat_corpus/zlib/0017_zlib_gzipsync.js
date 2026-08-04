const zlib = require('zlib');
const c = zlib.gzipSync('level one data', { level: 1 });
console.log(zlib.gunzipSync(c).toString('utf8'));
console.log(c.length > 0);
