const {EventEmitter} = require('events');
const e = new EventEmitter();
e.on('has', () => {});
console.log(e.emit('has'));
