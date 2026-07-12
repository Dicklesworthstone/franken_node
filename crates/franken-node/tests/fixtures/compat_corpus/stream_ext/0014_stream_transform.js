const {Transform} = require('stream');
const t = new Transform({
  transform(chunk, enc, cb) { cb(null, chunk.toString().toUpperCase()); }
});
t.on('data', (c) => console.log('out:' + c.toString()));
t.on('end', () => console.log('end'));
t.write('abc');
t.end('def');
