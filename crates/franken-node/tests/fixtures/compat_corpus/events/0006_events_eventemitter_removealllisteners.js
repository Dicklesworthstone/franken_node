const {EventEmitter} = require('events');
const e = new EventEmitter();
e.on('a', () => console.log('A'));
e.on('b', () => console.log('B'));
e.removeAllListeners('a');
e.emit('a');
e.emit('b');
console.log(e.listenerCount('a') + ',' + e.listenerCount('b'));
