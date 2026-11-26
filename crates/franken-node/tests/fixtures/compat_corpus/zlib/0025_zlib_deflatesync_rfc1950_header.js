const zlib = require('zlib');
const c = zlib.deflateSync('rfc1950 header verification');
const cmf = c[0];
const flg = c[1];
console.log(cmf & 0x0f);
console.log((cmf * 256 + flg) % 31);
console.log(zlib.inflateSync(c).toString('utf8'));
