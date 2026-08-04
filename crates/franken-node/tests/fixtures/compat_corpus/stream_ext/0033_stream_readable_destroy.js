const {Readable} = require('stream');
const r = new Readable({read() {}});
r.on('error', () => console.log('error-should-not-fire'));
r.on('close', () => console.log('close'));
console.log('before:' + r.destroyed);
r.destroy();
console.log('after:' + r.destroyed);
