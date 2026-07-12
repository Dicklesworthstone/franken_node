const {Writable} = require('stream');
const w = new Writable({
  write(chunk, enc, cb) { console.log('wrote:' + chunk.toString()); cb(); }
});
w.write('first');
w.write('second');
w.end('last');
