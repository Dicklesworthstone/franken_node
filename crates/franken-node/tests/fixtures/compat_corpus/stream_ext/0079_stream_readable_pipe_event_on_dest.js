const { Readable, Writable } = require('stream');
const src = Readable.from(['x']);
let pipedFromSrc = false;
const dst = new Writable({
  write(c, e, cb) { cb(); },
});
dst.on('pipe', (s) => {
  pipedFromSrc = (s === src);
});
dst.on('finish', () => {
  console.log('pipe-event-matched:' + pipedFromSrc);
});
src.pipe(dst);
