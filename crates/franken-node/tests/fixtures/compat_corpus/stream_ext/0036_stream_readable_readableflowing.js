const {Readable} = require('stream');
const r = Readable.from(['fl']);
console.log('initial:' + r.readableFlowing);
r.on('data', () => {});
console.log('after-on:' + r.readableFlowing);
r.pause();
console.log('after-pause:' + r.readableFlowing);
r.resume();
r.on('end', () => console.log('end'));
