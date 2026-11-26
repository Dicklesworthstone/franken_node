const {EventEmitter} = require('events');
const e = new EventEmitter();
console.log(e.setMaxListeners(0) === e);
console.log(e.getMaxListeners());
let sum = 0;
for (let i = 1; i <= 15; i++) {
  e.on('many', () => { sum += i; });
}
console.log(e.listenerCount('many'));
e.emit('many');
console.log(sum);
