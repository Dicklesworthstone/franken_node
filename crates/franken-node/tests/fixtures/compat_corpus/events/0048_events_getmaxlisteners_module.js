const events = require('events');
const {EventEmitter} = events;
const e = new EventEmitter();
console.log(events.getMaxListeners(e));
e.setMaxListeners(33);
console.log(events.getMaxListeners(e));
console.log(events.getMaxListeners(e) === e.getMaxListeners());
