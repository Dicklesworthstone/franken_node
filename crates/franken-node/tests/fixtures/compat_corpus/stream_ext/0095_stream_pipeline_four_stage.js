const { Readable, Transform, Writable, pipeline } = require('stream');
const src = Readable.from(['hello', 'world']);
const upper = new Transform({
  transform(c, e, cb) { cb(null, c.toString('utf8').toUpperCase()); },
});
const bracket = new Transform({
  transform(c, e, cb) { cb(null, '[' + c.toString('utf8') + ']'); },
});
const out = [];
const sink = new Writable({
  write(c, e, cb) { out.push(c.toString('utf8')); cb(); },
});
pipeline(src, upper, bracket, sink, (err) => {
  console.log('err:' + (err == null));
  console.log(out.join(''));
});
