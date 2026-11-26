const { Transform } = require('stream');
const events = [];
const t = new Transform({
  transform(chunk, enc, cb) {
    const s = chunk.toString('utf8');
    if (s === 'bad') return cb(new Error('bad-chunk'));
    this.push(s.toUpperCase());
    cb();
  },
});
t.on('data', (c) => events.push('data:' + c.toString('utf8')));
t.on('error', (err) => events.push('error:' + err.message));
t.on('end', () => events.push('end'));
t.on('close', () => {
  events.push('close');
  console.log(events.join('|'));
});
t.write('ok');
t.write('bad');
