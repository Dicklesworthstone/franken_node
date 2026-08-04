const zlib = require('zlib');
const c = zlib.gzipSync('magic check');
console.log(c[0] === 0x1f);
console.log(c[1] === 0x8b);
console.log(c[2] === 8);
