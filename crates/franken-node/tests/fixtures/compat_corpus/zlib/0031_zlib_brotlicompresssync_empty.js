const zlib = require('zlib');
const fromBuf = zlib.brotliDecompressSync(zlib.brotliCompressSync(Buffer.alloc(0)));
const fromStr = zlib.brotliDecompressSync(zlib.brotliCompressSync(''));
console.log(Buffer.isBuffer(fromBuf) && fromBuf.length === 0);
console.log(Buffer.isBuffer(fromStr) && fromStr.length === 0);
