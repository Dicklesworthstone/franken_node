const {EventEmitter} = require('events');
const e = new EventEmitter();
e.on('zeta', () => {});
e.on('alpha', () => {});
e.once('mid', () => {});
console.log(e.eventNames().slice().sort().join(','));
console.log(e.eventNames().length);
