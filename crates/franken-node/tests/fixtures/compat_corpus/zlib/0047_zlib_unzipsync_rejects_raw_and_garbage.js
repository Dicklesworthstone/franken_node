const zlib = require('zlib');
const raw = zlib.deflateRawSync('unframed raw deflate');
for (const [label, buf] of [['raw', raw], ['garbage', Buffer.from('garbage payload')]]) {
  try {
    zlib.unzipSync(buf);
    console.log(label + ':no-throw');
  } catch (err) {
    console.log(label + ':' + (err instanceof Error) + ':' + String(err.code));
  }
}
