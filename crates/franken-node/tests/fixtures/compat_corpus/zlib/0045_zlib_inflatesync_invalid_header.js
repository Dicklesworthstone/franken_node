const zlib = require('zlib');
try {
  zlib.inflateSync(Buffer.from('invalid zlib header bytes'));
  console.log('no-throw');
} catch (err) {
  console.log(err instanceof Error);
  console.log(String(err.code));
}
