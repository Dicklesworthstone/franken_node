const zlib = require('zlib');
const input = 'hello gzip world';
const out = zlib.gunzipSync(zlib.gzipSync(input)).toString('utf8');
console.log(out);
console.log(out === input);
