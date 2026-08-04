const {finished, Writable} = require('stream');
const w = new Writable({write(c, e, cb) { cb(); }});
finished(w, (err) => console.log('wfinished:' + (err == null)));
w.end('done');
