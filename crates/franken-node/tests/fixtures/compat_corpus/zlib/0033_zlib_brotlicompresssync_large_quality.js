const zlib = require('zlib');
const input = Buffer.from('brotli-repetitive-segment-0123456789-'.repeat(450));
const q0 = zlib.brotliCompressSync(input, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 0 } });
const q11 = zlib.brotliCompressSync(input, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 11 } });
console.log(q11.length <= q0.length);
console.log(q11.length < input.length / 10);
console.log(zlib.brotliDecompressSync(q0).equals(input));
console.log(zlib.brotliDecompressSync(q11).equals(input));
