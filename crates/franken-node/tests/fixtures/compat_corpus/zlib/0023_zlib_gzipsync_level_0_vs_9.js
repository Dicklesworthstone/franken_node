const zlib = require('zlib');
const input = Buffer.from('abcdefgh'.repeat(300));
const none = zlib.gzipSync(input, { level: zlib.constants.Z_NO_COMPRESSION });
const best = zlib.gzipSync(input, { level: zlib.constants.Z_BEST_COMPRESSION });
console.log(best.length < none.length);
console.log(none.length > input.length);
console.log(zlib.gunzipSync(none).equals(input));
console.log(zlib.gunzipSync(best).equals(input));
