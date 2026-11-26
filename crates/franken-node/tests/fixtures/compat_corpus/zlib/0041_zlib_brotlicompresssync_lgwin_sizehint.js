const zlib = require('zlib');
const input = Buffer.from('brotli params lgwin and size hint test '.repeat(50));
const opts = {
  params: {
    [zlib.constants.BROTLI_PARAM_QUALITY]: 4,
    [zlib.constants.BROTLI_PARAM_LGWIN]: 18,
    [zlib.constants.BROTLI_PARAM_SIZE_HINT]: input.length,
  },
};
const compressed = zlib.brotliCompressSync(input, opts);
const out = zlib.brotliDecompressSync(compressed);
console.log(compressed.length < input.length);
console.log(out.equals(input));
