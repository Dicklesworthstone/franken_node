const zlib = require('zlib');
zlib.gunzip(Buffer.from('garbage bytes here'), (err, result) => {
  console.log(err !== null);
  console.log(err instanceof Error);
  console.log(String(err.code));
  console.log(result === undefined);
});
