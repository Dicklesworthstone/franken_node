const zlib = require('zlib');
const utf8 = 'Async deflate UTF-8: café 日本語 🚀';
zlib.deflate(utf8, (e1, c1) => {
  zlib.inflate(c1, (e2, p1) => {
    zlib.deflate(Buffer.alloc(0), (e3, c2) => {
      zlib.inflate(c2, (e4, p2) => {
        console.log(e1 === null && e2 === null && e3 === null && e4 === null);
        console.log(p1.toString('utf8') === utf8);
        console.log(p2.length);
      });
    });
  });
});
