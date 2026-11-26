const { Writable } = require('stream');
const batches = [];
const w = new Writable({
  write(chunk, enc, cb) {
    batches.push('single:' + chunk.toString('utf8'));
    cb();
  },
  writev(chunks, cb) {
    batches.push('batch:' + chunks.map((item) => item.chunk.toString('utf8')).join('+'));
    cb();
  },
});
w.cork();
w.write('one');
w.write('two');
w.write('three');
w.uncork();
w.end('four', () => {
  console.log(batches.join('|'));
});
