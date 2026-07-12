const {Writable} = require('stream');
const w = new Writable({write(c, e, cb) { cb(); }});
w.on('error', (err) => console.log('event:' + err.code));
w.end();
w.write('late', (err) => console.log('cb:' + err.code));
