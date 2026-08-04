const {EventEmitter} = require('events');
const e = new EventEmitter();
const a = () => console.log('a');
const b = () => console.log('b');
e.on('ev', a);
e.on('ev', b);
e.removeListener('ev', a);
e.emit('ev');
