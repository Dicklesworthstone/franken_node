const {EventEmitter} = require('events');
const e = new EventEmitter();
const second = () => console.log('second');
e.on('r', () => { console.log('first'); e.removeListener('r', second); });
e.on('r', second);
e.emit('r');
console.log('count:' + e.listenerCount('r'));
e.emit('r');
