const {EventEmitter} = require('events');
const e = new EventEmitter();
console.log(e.addListener === e.on);
const out = [];
const ret = e.addListener('ping', (v) => out.push(v));
console.log(ret === e);
e.emit('ping', 'one');
e.emit('ping', 'two');
console.log(out.join(','));
