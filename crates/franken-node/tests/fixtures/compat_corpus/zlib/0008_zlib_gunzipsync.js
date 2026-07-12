const zlib = require('zlib');
try {
  zlib.gunzipSync(Buffer.from('this is not gzip data'));
  console.log('no-throw');
} catch (e) {
  console.log(e instanceof Error);
  console.log(String(e.code));
}
