const {Writable} = require('stream');
const w = new Writable({write(c, e, cb) { cb(); }});
w.on('finish', () => console.log('finish'));
w.on('close', () => console.log('close'));
w.end('bye');
