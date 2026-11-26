const zlib = require('zlib');
const corrupted = Buffer.from(zlib.gzipSync('integrity check payload for crc verification'));
corrupted[corrupted.length - 6] ^= 0xff;
try {
  zlib.gunzipSync(corrupted);
  console.log('no-throw');
} catch (err) {
  console.log(err instanceof Error);
  console.log(String(err.code));
}
