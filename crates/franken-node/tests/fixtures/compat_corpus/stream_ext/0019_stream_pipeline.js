const {pipeline, Readable, Writable} = require('stream');
const w = new Writable({write(c, e, cb) { console.log('got:' + c.toString()); cb(); }});
pipeline(Readable.from(['pl']), w, (err) => {
  console.log('clean:' + (err == null));
});
