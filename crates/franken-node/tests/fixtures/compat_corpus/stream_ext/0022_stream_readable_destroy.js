const {Readable} = require('stream');
const r = new Readable({read() {}});
r.on('error', (err) => console.log('error:' + err.message));
r.on('close', () => console.log('close'));
r.destroy(new Error('killed'));
console.log('destroyed:' + r.destroyed);
