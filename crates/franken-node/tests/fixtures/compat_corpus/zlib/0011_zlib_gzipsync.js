const zlib = require('zlib');
const a = zlib.gzipSync('same input');
const b = zlib.gzipSync(Buffer.from('same input', 'utf8'));
console.log(a.equals(b));
console.log(zlib.gunzipSync(a).toString('utf8'));
