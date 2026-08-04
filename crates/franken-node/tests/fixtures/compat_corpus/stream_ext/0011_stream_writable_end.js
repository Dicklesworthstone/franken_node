const {Writable} = require('stream');
const w = new Writable({write(c, e, cb) { cb(); }});
let events = 0;
let cbRan = false;
w.on('finish', () => events++);
w.write('x');
w.end(() => { cbRan = true; });
setImmediate(() => setImmediate(() => console.log('finish-count:' + events + ',cb:' + cbRan)));
