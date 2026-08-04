const {pipeline, Readable, Transform, Writable} = require('stream');
const up = new Transform({transform(c, e, cb) { cb(null, c.toString().toUpperCase()); }});
const out = [];
const w = new Writable({write(c, e, cb) { out.push(c.toString()); cb(); }});
pipeline(Readable.from(['aa', 'bb']), up, w, (err) => {
  console.log((err == null) + ':' + out.join(','));
});
