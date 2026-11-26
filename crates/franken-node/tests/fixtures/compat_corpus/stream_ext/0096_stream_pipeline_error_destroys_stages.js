const { Readable, Transform, Writable, pipeline } = require('stream');
const src = Readable.from(['ok', 'boom', 'never']);
const mid = new Transform({
  transform(c, e, cb) {
    const s = c.toString('utf8');
    if (s === 'boom') return cb(new Error('mid-exploded'));
    cb(null, s);
  },
});
const sink = new Writable({ write(c, e, cb) { cb(); } });
pipeline(src, mid, sink, (err) => {
  console.log('err:' + (err ? err.message : 'none'));
  console.log('destroyed:', src.destroyed, mid.destroyed, sink.destroyed);
});
