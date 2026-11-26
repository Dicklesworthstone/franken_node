const { Writable } = require('stream');
const events = [];
const w = new Writable({
  write(chunk, enc, cb) {
    events.push('write:' + chunk.toString('utf8'));
    cb();
  },
});
w.on('finish', () => events.push('finish'));
w.end('68656c6c6f', 'hex', () => {
  events.push('end-cb');
  console.log(events.join('|'));
});
