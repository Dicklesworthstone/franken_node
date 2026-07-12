const {EventEmitter} = require('events');
const e = new EventEmitter();
console.log(e.getMaxListeners());
console.log(e.setMaxListeners(25) === e);
console.log(e.getMaxListeners());
