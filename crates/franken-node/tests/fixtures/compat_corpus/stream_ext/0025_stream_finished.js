const {finished, Readable} = require('stream');
const r = Readable.from(['f']);
r.on('data', () => {});
finished(r, (err) => console.log('finished:' + (err == null)));
