const zlib = require('zlib');
const payload = 'rfc1952 trailer isize verification payload 0123456789';
const c = zlib.gzipSync(payload);
const isize = c.readUInt32LE(c.length - 4);
console.log(isize === Buffer.byteLength(payload, 'utf8'));
console.log(isize);
