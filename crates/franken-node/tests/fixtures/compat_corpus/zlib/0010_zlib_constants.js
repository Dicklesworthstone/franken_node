const zlib = require('zlib');
console.log(zlib.constants.Z_BEST_COMPRESSION === 9);
console.log(zlib.constants.Z_NO_COMPRESSION === 0);
console.log(zlib.constants.Z_DEFAULT_COMPRESSION === -1);
console.log(typeof zlib.constants.BROTLI_PARAM_QUALITY);
