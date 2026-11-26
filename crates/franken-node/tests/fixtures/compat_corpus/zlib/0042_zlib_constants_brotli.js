const zlib = require('zlib');
const c = zlib.constants;
console.log(c.BROTLI_MODE_GENERIC === 0);
console.log(c.BROTLI_MODE_TEXT === 1);
console.log(c.BROTLI_MODE_FONT === 2);
console.log(c.BROTLI_DEFAULT_QUALITY === 11);
console.log(c.BROTLI_DEFAULT_WINDOW === 22);
console.log(typeof c.BROTLI_PARAM_LGWIN === 'number' && typeof c.BROTLI_PARAM_LGBLOCK === 'number');
