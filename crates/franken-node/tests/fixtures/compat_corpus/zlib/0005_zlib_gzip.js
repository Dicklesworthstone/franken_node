const zlib = require('zlib');
zlib.gzip('async gzip data', (err, compressed) => {
  console.log(err === null);
  zlib.gunzip(compressed, (err2, plain) => {
    console.log(err2 === null);
    console.log(plain.toString('utf8'));
  });
});
