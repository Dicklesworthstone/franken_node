const {EventEmitter} = require('events');
const e = new EventEmitter();
e.on('m', () => {});
e.on('m', () => {});
e.once('m', () => {});
console.log(e.listenerCount('m'));
e.emit('m');
console.log(e.listenerCount('m'));
