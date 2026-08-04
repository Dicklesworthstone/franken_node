const {EventEmitter} = require('events');
const e = new EventEmitter();
const fn = () => console.log('should-not-print');
e.on('x', fn);
e.off('x', fn);
console.log(e.emit('x'));
console.log(e.listenerCount('x'));
