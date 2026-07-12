const {PassThrough, Writable} = require('stream');
const src = new PassThrough();
const got = [];
const dst = new Writable({write(c, e, cb) { got.push(c.toString()); cb(); }});
dst.on('unpipe', () => console.log('unpipe-event'));
src.pipe(dst);
src.write('kept');
setImmediate(() => {
  src.unpipe(dst);
  src.write('dropped');
  setImmediate(() => console.log('got:' + got.join(',')));
});
