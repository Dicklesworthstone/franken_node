const { Writable } = require('stream');
const written = [];
const w = new Writable({
  write(chunk, enc, cb) {
    written.push(chunk.toString('utf8'));
    cb();
  },
});
w.cork();
w.cork();
w.write('a');
w.write('b');
console.log('corked2:' + w.writableCorked + ':' + written.length);
w.uncork();
console.log('corked1:' + w.writableCorked + ':' + written.length);
w.uncork();
w.end(() => {
  console.log('final:' + w.writableCorked + ':' + written.join(','));
});
