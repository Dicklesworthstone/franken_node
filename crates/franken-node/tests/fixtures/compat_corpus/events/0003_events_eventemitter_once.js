const {EventEmitter} = require('events');
const e = new EventEmitter();
let n = 0;
e.once('hit', () => n++);
e.emit('hit');
e.emit('hit');
e.emit('hit');
console.log(n);
console.log(e.listenerCount('hit'));
