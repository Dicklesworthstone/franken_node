const {EventEmitter} = require('events');
const e = new EventEmitter();
console.log(e.emit('nobody'));
console.log(e.emit('nobody', 1, 2));
