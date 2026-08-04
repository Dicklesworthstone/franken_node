const {Writable} = require('stream');
const w = new Writable({highWaterMark: 1, write(c, e, cb) { setImmediate(cb); }});
const ok = w.write('xyz');
console.log('needs-drain:' + !ok);
w.on('drain', () => { console.log('drain'); w.end(() => console.log('ended')); });
