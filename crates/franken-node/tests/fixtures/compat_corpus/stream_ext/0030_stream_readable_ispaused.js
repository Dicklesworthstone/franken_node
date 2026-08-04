const {Readable} = require('stream');
const r = new Readable({read() {}});
console.log('initial:' + r.isPaused());
r.pause();
console.log('paused:' + r.isPaused());
r.resume();
console.log('resumed:' + r.isPaused());
r.push(null);
