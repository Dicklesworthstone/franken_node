const {PassThrough} = require('stream');
const p = new PassThrough();
const out = [];
p.on('data', (c) => out.push(c.toString()));
p.on('end', () => console.log(out.join(',')));
p.write('1');
p.write('2');
p.end('3');
