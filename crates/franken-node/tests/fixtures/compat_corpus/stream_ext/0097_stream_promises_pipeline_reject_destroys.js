const { Readable, Transform, Writable } = require('stream');
const { pipeline } = require('stream/promises');
(async () => {
  const src = Readable.from(['a', 'b']);
  const fail = new Transform({
    transform(c, e, cb) { cb(new Error('promise-pipe-fail')); },
  });
  const sink = new Writable({ write(c, e, cb) { cb(); } });
  try {
    await pipeline(src, fail, sink);
    console.log('no-throw');
  } catch (err) {
    console.log('caught:' + err.message);
    console.log('destroyed:', src.destroyed, fail.destroyed, sink.destroyed);
  }
})();
