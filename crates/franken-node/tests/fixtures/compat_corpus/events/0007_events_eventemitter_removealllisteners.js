const {EventEmitter} = require('events');
const e = new EventEmitter();
e.on('a', () => console.log('A'));
e.on('b', () => console.log('B'));
console.log(e.removeAllListeners() === e);
console.log(e.eventNames().length);
console.log(String(e.emit('a')) + ',' + String(e.emit('b')));
