const {Writable} = require('stream');
const w = new Writable({write(c, e, cb) { cb(); }});
w.on('finish', () => console.log('finish-should-not-fire'));
w.on('close', () => console.log('close'));
w.write('a');
w.destroy();
console.log('destroyed:' + w.destroyed);
