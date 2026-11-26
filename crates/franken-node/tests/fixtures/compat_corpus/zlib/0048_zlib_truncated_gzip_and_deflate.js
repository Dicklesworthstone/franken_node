const zlib = require('zlib');
const g = zlib.gzipSync('truncated gzip buffer test');
const d = zlib.deflateSync('truncated deflate buffer test');
for (const [label, fn] of [
  ['gzip', () => zlib.gunzipSync(g.subarray(0, g.length - 4))],
  ['deflate', () => zlib.inflateSync(d.subarray(0, d.length - 3))],
]) {
  try {
    fn();
    console.log(label + ':no-throw');
  } catch (err) {
    console.log(label + ':' + (err instanceof Error) + ':' + String(err.code).startsWith('Z_'));
  }
}
