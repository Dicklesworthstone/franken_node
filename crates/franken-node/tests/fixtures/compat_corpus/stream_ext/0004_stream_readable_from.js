const {Readable} = require('stream');
const r = Readable.from(['one']);
r.on('data', (c) => console.log('data:' + c));
r.on('end', () => console.log('end'));
r.on('close', () => console.log('close'));
