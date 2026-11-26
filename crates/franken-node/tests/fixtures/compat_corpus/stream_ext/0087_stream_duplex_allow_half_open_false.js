const { Duplex } = require('stream');
const events = [];
const d = new Duplex({
  allowHalfOpen: false,
  read() {
    this.push('msg');
    this.push(null);
  },
  write(chunk, enc, cb) {
    events.push('write:' + chunk.toString('utf8'));
    cb();
  },
});
d.on('data', (c) => events.push('data:' + c.toString('utf8')));
d.on('end', () => events.push('end'));
d.on('finish', () => {
  events.push('finish');
  console.log('allowHalfOpen:' + d.allowHalfOpen);
  console.log(events.join('|'));
});
