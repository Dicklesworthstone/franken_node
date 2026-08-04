const {Readable} = require('stream');
const r = Readable.from(['a', 'b', 'c']);
const out = [];
r.on('data', (c) => out.push(String(c)));
r.on('end', () => console.log(out.join(',') + '|end'));
