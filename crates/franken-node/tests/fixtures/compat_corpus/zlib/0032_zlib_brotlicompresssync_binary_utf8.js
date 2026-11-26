const zlib = require('zlib');
const bin = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
const text = 'Brotli UTF-8: Καλημέρα こんにちは 🌍';
const outBin = zlib.brotliDecompressSync(zlib.brotliCompressSync(bin));
const outText = zlib.brotliDecompressSync(zlib.brotliCompressSync(text)).toString('utf8');
console.log(outBin.equals(bin));
console.log(outText === text);
console.log(outText);
