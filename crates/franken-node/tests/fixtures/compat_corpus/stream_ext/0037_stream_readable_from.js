const {Readable} = require('stream');
const r = Readable.from([]);
let n = 0;
r.on('data', () => n++);
r.on('end', () => console.log('end:' + n));
r.on('close', () => console.log('close'));
