const zlib = require('zlib');
const input = Buffer.from('async-gzip-level-test-'.repeat(200));
zlib.gzip(input, { level: 0 }, (e0, c0) => {
  zlib.gzip(input, { level: 9 }, (e9, c9) => {
    zlib.gunzip(c9, (ed, plain) => {
      console.log(e0 === null && e9 === null && ed === null);
      console.log(c9.length < c0.length);
      console.log(plain.equals(input));
    });
  });
});
