const zlib = require('zlib');
const bin = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
zlib.gzip(bin, (e1, c1) => {
  zlib.gunzip(c1, (e2, p1) => {
    zlib.gzip(Buffer.alloc(0), (e3, c2) => {
      zlib.gunzip(c2, (e4, p2) => {
        console.log(e1 === null && e2 === null && e3 === null && e4 === null);
        console.log(p1.equals(bin));
        console.log(p2.length);
      });
    });
  });
});
