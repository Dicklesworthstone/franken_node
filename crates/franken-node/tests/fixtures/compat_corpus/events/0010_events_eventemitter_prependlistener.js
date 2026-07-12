const {EventEmitter} = require('events');
const e = new EventEmitter();
e.on('p', () => console.log('appended'));
e.prependListener('p', () => console.log('prepended'));
e.emit('p');
