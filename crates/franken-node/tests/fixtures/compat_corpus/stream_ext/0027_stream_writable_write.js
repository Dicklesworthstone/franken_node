const {Writable} = require('stream');
const w = new Writable({highWaterMark: 100, write(c, e, cb) { setImmediate(cb); }});
console.log('small:' + w.write('ab'));
const w2 = new Writable({highWaterMark: 2, write(c, e, cb) { setImmediate(cb); }});
console.log('big:' + w2.write('abcdef'));
w.end();
w2.end();
