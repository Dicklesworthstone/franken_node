const zlib = require('zlib');
const input = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
const compressed = zlib.gzipSync(input);
const out = zlib.gunzipSync(compressed);
console.log(Buffer.isBuffer(out));
console.log(out.length);
console.log(out.equals(input));
console.log(out[0] + ',' + out[127] + ',' + out[255]);
