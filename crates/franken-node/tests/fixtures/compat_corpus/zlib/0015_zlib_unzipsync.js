const zlib = require('zlib');
console.log(zlib.unzipSync(zlib.gzipSync('via gzip')).toString('utf8'));
console.log(zlib.unzipSync(zlib.deflateSync('via deflate')).toString('utf8'));
