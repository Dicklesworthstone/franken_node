const {Readable} = require('stream');
async function* gen() { yield 'x'; yield 'y'; yield 'z'; }
const r = Readable.from(gen());
const out = [];
r.on('data', (c) => out.push(String(c)));
r.on('end', () => console.log(out.join('-')));
