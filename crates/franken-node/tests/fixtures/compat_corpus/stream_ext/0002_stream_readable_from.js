const {Readable} = require('stream');
const r = Readable.from('hello');
const chunks = [];
r.on('data', (c) => chunks.push(String(c)));
r.on('end', () => console.log(chunks.length + ':' + chunks.join('')));
