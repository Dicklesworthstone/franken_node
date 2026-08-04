const zlib = require('zlib');
const input = Buffer.from('0123456789abcdef'.repeat(640));
const c = zlib.gzipSync(input);
const out = zlib.gunzipSync(c);
console.log(input.length);
console.log(out.length === input.length);
console.log(out.equals(input));
console.log(c.length < input.length);
