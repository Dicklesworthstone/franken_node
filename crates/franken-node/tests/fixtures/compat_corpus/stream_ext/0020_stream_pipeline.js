const {pipeline, Readable, Writable} = require('stream');
const r = new Readable({read() { this.destroy(new Error('src-fail')); }});
const w = new Writable({write(c, e, cb) { cb(); }});
pipeline(r, w, (err) => {
  console.log('err:' + (err ? err.message : 'none'));
});
