const {Readable} = require('stream');
const r = new Readable({read() {}});
r.setEncoding('utf8');
r.on('data', (c) => console.log(typeof c + ':' + c));
r.on('end', () => console.log('end'));
r.push(Buffer.from('enc'));
r.push(null);
