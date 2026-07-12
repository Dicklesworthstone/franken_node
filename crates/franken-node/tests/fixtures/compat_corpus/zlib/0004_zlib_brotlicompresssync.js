const zlib = require('zlib');
const input = 'brotli roundtrip content';
const out = zlib.brotliDecompressSync(zlib.brotliCompressSync(input)).toString('utf8');
console.log(out);
console.log(out === input);
