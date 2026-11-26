const zlib = require('zlib');
const msg = 'cross-mode gzip sync/async interop';
const syncComp = zlib.gzipSync(msg);
zlib.gunzip(syncComp, (e1, plain1) => {
  zlib.gzip(msg, (e2, asyncComp) => {
    const plain2 = zlib.gunzipSync(asyncComp);
    console.log(e1 === null && e2 === null);
    console.log(plain1.toString('utf8') === msg);
    console.log(plain2.toString('utf8') === msg);
  });
});
