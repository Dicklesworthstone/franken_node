const {EventEmitter} = require('events');
const e = new EventEmitter();
const out = [];
e.on('tick', () => out.push('a'));
e.emit('tick');
e.emit('tick');
console.log(out.join(','));
