const { Readable } = require('stream');
function* seq() {
  yield 'gen-1';
  yield 'gen-2';
  yield 'gen-3';
}
const r = Readable.from(seq());
const out = [];
r.on('data', (c) => out.push(c));
r.on('end', () => console.log(out.join(',')));
