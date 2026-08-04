const zlib = require('zlib');
const opts = { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } };
const c = zlib.brotliCompressSync('brotli with quality option', opts);
console.log(zlib.brotliDecompressSync(c).toString('utf8'));
