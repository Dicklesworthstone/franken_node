const zlib = require('zlib');
const allBytes = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
const outAll = zlib.inflateRawSync(zlib.deflateRawSync(allBytes));
const outEmpty = zlib.inflateRawSync(zlib.deflateRawSync(Buffer.alloc(0)));
console.log(outAll.equals(allBytes));
console.log(outAll.length);
console.log(outEmpty.length);
