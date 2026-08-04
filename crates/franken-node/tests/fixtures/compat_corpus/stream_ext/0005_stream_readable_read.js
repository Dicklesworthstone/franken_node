const {Readable} = require('stream');
const r = new Readable({read() {}});
r.push('pq');
r.push(null);
r.on('readable', () => {
  let chunk;
  while ((chunk = r.read()) !== null) console.log('read:' + chunk.toString());
});
r.on('end', () => console.log('end'));
