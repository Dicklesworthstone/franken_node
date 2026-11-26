const zlib = require('zlib');
const full = zlib.brotliCompressSync('truncated brotli stream payload '.repeat(20));
const truncated = full.subarray(0, Math.max(2, Math.floor(full.length / 2)));
try {
  zlib.brotliDecompressSync(truncated);
  console.log('no-throw');
} catch (err) {
  console.log(err instanceof Error);
}
