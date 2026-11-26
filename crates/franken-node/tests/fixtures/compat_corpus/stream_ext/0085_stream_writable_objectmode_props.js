const { Writable } = require('stream');
const seen = [];
const pending = [];
const w = new Writable({
  objectMode: true,
  write(obj, enc, cb) {
    seen.push(obj.id);
    pending.push(cb);
  },
});
console.log(w.writableObjectMode, w.writableHighWaterMark);
w.write({ id: 1 });
w.write({ id: 2 });
console.log('buffered:' + w.writableLength);
while (pending.length) pending.shift()();
w.end({ id: 3 }, () => {
  console.log('seen:' + seen.join(','));
});
