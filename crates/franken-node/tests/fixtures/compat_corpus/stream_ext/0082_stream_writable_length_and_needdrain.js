const { Writable } = require('stream');
const pending = [];
const w = new Writable({
  highWaterMark: 4,
  write(chunk, enc, cb) {
    pending.push(cb);
  },
});
console.log('hwm:' + w.writableHighWaterMark);
const ok1 = w.write('ab');
console.log('after1:', ok1, w.writableLength, w.writableNeedDrain);
const ok2 = w.write('cdef');
console.log('after2:', ok2, w.writableLength, w.writableNeedDrain);
w.on('drain', () => {
  console.log('drained:', w.writableLength, w.writableNeedDrain);
});
while (pending.length) pending.shift()();
