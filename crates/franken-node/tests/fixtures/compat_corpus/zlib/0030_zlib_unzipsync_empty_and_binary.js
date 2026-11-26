const zlib = require('zlib');
const bin = Buffer.from(Array.from({ length: 256 }, (_, i) => (i * 37) & 0xff));
console.log(zlib.unzipSync(zlib.gzipSync(Buffer.alloc(0))).length);
console.log(zlib.unzipSync(zlib.deflateSync(Buffer.alloc(0))).length);
console.log(zlib.unzipSync(zlib.gzipSync(bin)).equals(bin));
console.log(zlib.unzipSync(zlib.deflateSync(bin)).equals(bin));
