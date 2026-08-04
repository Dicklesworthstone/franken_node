const {Readable} = require('stream');
const r = Readable.from([{id: 1}, {id: 2}], {objectMode: true});
r.on('data', (o) => console.log('id:' + o.id + ':' + typeof o));
r.on('end', () => console.log('end'));
