const zlib = require('zlib');
const input = Buffer.from('compare raw deflate against zlib framed deflate');
const raw = zlib.deflateRawSync(input);
const framed = zlib.deflateSync(input);
console.log(raw.length < framed.length);
console.log(framed.length - raw.length);
console.log(zlib.inflateRawSync(raw).equals(input));
