const { Readable, Writable } = require('stream');
const src = Readable.from(['hello-', 'world-']);
const out = [];
const dst = new Writable({
  write(c, e, cb) {
    out.push(c.toString('utf8'));
    cb();
  },
});
src.pipe(dst, { end: false });
src.on('end', () => {
  console.log('ended-after-pipe:' + dst.writableEnded);
  dst.write('tail');
  dst.end(() => {
    console.log('combined:' + out.join(''));
    console.log('ended-after-end:' + dst.writableEnded);
  });
});
