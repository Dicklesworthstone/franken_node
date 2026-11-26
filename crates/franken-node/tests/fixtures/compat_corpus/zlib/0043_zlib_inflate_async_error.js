const zlib = require('zlib');
zlib.inflate(Buffer.from('not valid deflate payload'), (err, result) => {
  console.log(err !== null);
  console.log(err instanceof Error);
  console.log(String(err.code));
  console.log(result === undefined);
});
