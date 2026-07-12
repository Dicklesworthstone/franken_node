const {EventEmitter} = require('events');
const e = new EventEmitter();
console.log(e.on('a', () => {}) === e);
console.log(e.once('b', () => {}) === e);
console.log(e.prependListener('c', () => {}) === e);
