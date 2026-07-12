const {Readable} = require('stream');
const r = new Readable({read() {}});
r.setEncoding('utf8');
r.push('xyz');
r.push(null);
r.once('readable', () => {
  const first = r.read(1);
  r.unshift(first);
  console.log('back:' + r.read(3));
  console.log('after:' + String(r.read()));
});
