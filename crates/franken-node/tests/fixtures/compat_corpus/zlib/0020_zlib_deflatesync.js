const zlib = require('zlib');
const dict = Buffer.from('the quick brown fox');
const c = zlib.deflateSync('the quick brown fox jumps', { dictionary: dict });
const out = zlib.inflateSync(c, { dictionary: dict });
console.log(out.toString('utf8'));
