const { Readable } = require('stream');
const buf = Buffer.from('single-buffer-chunk', 'utf8');
const r = Readable.from(buf);
const chunks = [];
r.on('data', (c) => chunks.push(c));
r.on('end', () => {
  console.log(chunks.length);
  console.log(Buffer.isBuffer(chunks[0]));
  console.log(chunks[0].toString('utf8'));
});
