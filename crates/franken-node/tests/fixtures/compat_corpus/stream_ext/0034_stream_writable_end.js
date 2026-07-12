const {Writable} = require('stream');
const w = new Writable({write(c, e, cb) { cb(); }});
console.log('ended-before:' + w.writableEnded);
w.on('finish', () => console.log('finished-flag:' + w.writableFinished));
w.end('z');
console.log('ended-after:' + w.writableEnded);
