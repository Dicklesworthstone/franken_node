const zlib = require('zlib');
const input = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
const out = zlib.inflateSync(zlib.deflateSync(input));
console.log(out.length);
console.log(out.equals(input));
console.log(out[0] + ',' + out[128] + ',' + out[255]);
