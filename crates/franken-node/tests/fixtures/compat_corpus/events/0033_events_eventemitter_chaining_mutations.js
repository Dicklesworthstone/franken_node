const {EventEmitter} = require('events');
const e = new EventEmitter();
const fn = () => {};
console.log(e.prependOnceListener('p', fn) === e);
console.log(e.removeListener('p', fn) === e);
console.log(e.off('p', fn) === e);
console.log(e.removeAllListeners('p') === e);
console.log(e.listenerCount('p'));
