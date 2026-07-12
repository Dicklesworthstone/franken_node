const zlib = require('zlib');
zlib.deflate('nested callbacks', (err, c) => {
  zlib.inflate(c, (err2, p) => {
    console.log(p.toString('utf8'));
    console.log(err === null && err2 === null);
  });
});
