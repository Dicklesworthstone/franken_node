const {Readable} = require('stream');
const r = new Readable({objectMode: true, read() {}});
console.log(r.readableHighWaterMark);
console.log(r.readableObjectMode);
r.push(null);
