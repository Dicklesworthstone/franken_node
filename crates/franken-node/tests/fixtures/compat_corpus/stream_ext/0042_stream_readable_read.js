const {Readable} = require('stream');
const r = new Readable({read() {}});
r.setEncoding('utf8');
r.push('abcdef');
r.push(null);
r.on('readable', () => {
  let c;
  while ((c = r.read(2)) !== null) console.log('chunk:' + c);
});
r.on('end', () => console.log('end'));
