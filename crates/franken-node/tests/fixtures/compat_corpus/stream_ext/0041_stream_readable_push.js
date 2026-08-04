const {Readable} = require('stream');
const r = new Readable({read() {}});
r.on('error', (err) => console.log('error:' + err.code));
r.push(null);
console.log('ret:' + r.push('late'));
