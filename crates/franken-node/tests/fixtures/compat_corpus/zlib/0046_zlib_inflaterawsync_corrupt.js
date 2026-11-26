const zlib = require('zlib');
try {
  zlib.inflateRawSync(Buffer.from([0xff, 0xff, 0xff, 0xff]));
  console.log('no-throw');
} catch (err) {
  console.log(err instanceof Error);
  console.log(String(err.code));
}
