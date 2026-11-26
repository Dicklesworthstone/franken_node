const zlib = require('zlib');
const text = 'héllo 世界 Привет 🚀 café naïve — 日本語';
const out = zlib.gunzipSync(zlib.gzipSync(text)).toString('utf8');
console.log(out === text);
console.log(Buffer.byteLength(out, 'utf8') === Buffer.byteLength(text, 'utf8'));
console.log(out);
