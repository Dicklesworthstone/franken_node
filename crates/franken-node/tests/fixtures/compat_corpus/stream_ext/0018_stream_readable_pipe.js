const {Readable, PassThrough} = require('stream');
const r = Readable.from(['z']);
const p = new PassThrough();
console.log(r.pipe(p) === p);
p.on('data', () => {});
p.on('end', () => console.log('done'));
