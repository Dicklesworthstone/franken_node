const {EventEmitter} = require('events');
const e = new EventEmitter();
e.on('error', (err) => console.log('handled:' + err.message));
console.log(e.emit('error', new Error('soft')));
