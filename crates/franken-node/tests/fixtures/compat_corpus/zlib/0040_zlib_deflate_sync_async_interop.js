const zlib = require('zlib');
const msg = 'cross-mode deflate sync/async interop';
const syncComp = zlib.deflateSync(msg);
zlib.inflate(syncComp, (e1, plain1) => {
  zlib.deflate(msg, (e2, asyncComp) => {
    const plain2 = zlib.inflateSync(asyncComp);
    console.log(e1 === null && e2 === null);
    console.log(plain1.toString('utf8') === msg);
    console.log(plain2.toString('utf8') === msg);
  });
});
