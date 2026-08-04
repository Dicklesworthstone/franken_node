const {EventEmitter} = require('events');
const e = new EventEmitter();
e.on('c', () => console.log('fired'));
const list = e.listeners('c');
list.length = 0;
console.log(e.listenerCount('c'));
e.emit('c');
