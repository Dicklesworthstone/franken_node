const {EventEmitter} = require('events');
const e = new EventEmitter();
e.on('p', () => console.log('normal'));
e.prependOnceListener('p', () => console.log('front-once'));
e.emit('p');
e.emit('p');
