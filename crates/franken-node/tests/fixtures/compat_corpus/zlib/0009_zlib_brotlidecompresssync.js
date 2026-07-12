const zlib = require('zlib');
try {
  zlib.brotliDecompressSync(Buffer.from([1, 2, 3, 4, 5]));
  console.log('no-throw');
} catch (e) {
  console.log(e instanceof Error);
}
