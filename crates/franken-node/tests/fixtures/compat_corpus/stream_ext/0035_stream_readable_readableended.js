const {Readable} = require('stream');
const r = Readable.from(['e']);
console.log('before:' + r.readableEnded);
r.on('data', () => {});
r.on('end', () => console.log('at-end:' + r.readableEnded));
