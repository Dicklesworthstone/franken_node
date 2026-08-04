const {EventEmitter} = require('events');
const e = new EventEmitter();
e.on('go', () => console.log('first'));
e.on('go', () => console.log('second'));
e.on('go', () => console.log('third'));
e.emit('go');
