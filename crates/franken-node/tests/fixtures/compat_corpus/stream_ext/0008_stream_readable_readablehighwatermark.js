const {Readable, Writable} = require('stream');
const r = new Readable({highWaterMark: 4, read() {}});
const w = new Writable({highWaterMark: 8, write(c, e, cb) { cb(); }});
console.log(r.readableHighWaterMark);
console.log(w.writableHighWaterMark);
console.log(typeof new Readable({read() {}}).readableHighWaterMark === 'number');
