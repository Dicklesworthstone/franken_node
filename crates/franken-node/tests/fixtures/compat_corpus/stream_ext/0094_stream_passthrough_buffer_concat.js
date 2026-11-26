const { PassThrough } = require('stream');
const pt = new PassThrough();
const chunks = [];
pt.on('data', (c) => chunks.push(c));
pt.on('end', () => {
  const joined = Buffer.concat(chunks);
  console.log(Buffer.isBuffer(joined), joined.length);
  console.log(joined.toString('hex'));
});
pt.write(Buffer.from([0x00, 0x01, 0x7f]));
pt.end(Buffer.from([0x80, 0xfe, 0xff]));
