const zlib = require('zlib');
const input = 'deflate me please';
const out = zlib.inflateSync(zlib.deflateSync(input)).toString('utf8');
console.log(out);
console.log(out.length);
