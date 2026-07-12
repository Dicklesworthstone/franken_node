const zlib = require('zlib');
const input = Buffer.from('raw deflate data');
const out = zlib.inflateRawSync(zlib.deflateRawSync(input));
console.log(out.toString('utf8'));
console.log(out.equals(input));
