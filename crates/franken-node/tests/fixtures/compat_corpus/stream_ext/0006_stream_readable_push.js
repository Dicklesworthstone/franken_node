const {Readable} = require('stream');
const items = ['n1', 'n2'];
const r = new Readable({
  read() { this.push(items.length ? items.shift() : null); }
});
const out = [];
r.on('data', (c) => out.push(c.toString()));
r.on('end', () => console.log(out.join(',')));
