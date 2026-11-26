const { Readable } = require('stream');
const s = new Set(['red', 'green', 'red', 'blue']);
const r = Readable.from(s);
const out = [];
r.on('data', (c) => out.push(c));
r.on('end', () => console.log(out.join('|')));
