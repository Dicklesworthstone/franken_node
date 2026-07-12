const zlib = require('zlib');
const input = Buffer.from('aaaaaaaaaa'.repeat(200));
const best = zlib.deflateSync(input, { level: 9 });
const none = zlib.deflateSync(input, { level: 0 });
console.log(best.length < none.length);
console.log(none.length > input.length);
