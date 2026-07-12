const {Readable} = require('stream');
const r = new Readable({read() {}});
const seen = [];
r.on('readable', () => {
  let c;
  while ((c = r.read()) !== null) seen.push(c.toString());
});
r.on('end', () => console.log(seen.join(',')));
r.push('r1');
r.push('r2');
r.push(null);
