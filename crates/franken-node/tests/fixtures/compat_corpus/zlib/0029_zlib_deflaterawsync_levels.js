const zlib = require('zlib');
const input = Buffer.from('raw-level-pattern-'.repeat(250));
const l0 = zlib.deflateRawSync(input, { level: 0 });
const l9 = zlib.deflateRawSync(input, { level: 9 });
console.log(l9.length < l0.length);
console.log(zlib.inflateRawSync(l0).equals(input));
console.log(zlib.inflateRawSync(l9).equals(input));
