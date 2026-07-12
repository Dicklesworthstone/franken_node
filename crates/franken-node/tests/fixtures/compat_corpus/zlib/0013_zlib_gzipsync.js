const zlib = require('zlib');
console.log(zlib.gunzipSync(zlib.gzipSync(Buffer.alloc(0))).length);
console.log(zlib.inflateSync(zlib.deflateSync('')).length);
