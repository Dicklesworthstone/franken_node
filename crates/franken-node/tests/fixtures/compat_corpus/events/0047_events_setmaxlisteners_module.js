const events = require('events');
const {EventEmitter} = events;
const a = new EventEmitter();
const b = new EventEmitter();
events.setMaxListeners(17, a, b);
console.log(a.getMaxListeners());
console.log(b.getMaxListeners());
events.setMaxListeners(0, a);
console.log(a.getMaxListeners() + ',' + b.getMaxListeners());
