const zlib = require('zlib');
const dict = Buffer.from('shared preset dictionary phrase');
const compressed = zlib.deflateSync('shared preset dictionary phrase with tail', { dictionary: dict });
try {
  zlib.inflateSync(compressed);
  console.log('no-throw');
} catch (err) {
  console.log(err instanceof Error);
  console.log(String(err.code));
}
