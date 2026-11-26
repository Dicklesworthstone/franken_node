const {EventEmitter} = require('events');
const e = new EventEmitter();
console.log(e.off === e.removeListener);
const fn = () => {};
console.log(e.off('missing', fn) === e);
e.on('a', () => console.log('kept'));
console.log(e.off('a', fn) === e);
console.log(e.listenerCount('a'));
e.emit('a');
