const {Readable, Writable} = require('stream');
const r = Readable.from(['p1', 'p2']);
const got = [];
const w = new Writable({write(c, e, cb) { got.push(c.toString()); cb(); }});
w.on('finish', () => console.log(got.join(',')));
r.pipe(w);
