const {Transform} = require('stream');
const t = new Transform({
  transform(c, e, cb) { cb(null, c); },
  flush(cb) { this.push('FLUSHED'); cb(); }
});
const out = [];
t.on('data', (c) => out.push(c.toString()));
t.on('end', () => console.log(out.join('|')));
t.end('body');
