const {EventEmitter} = require('events');
const e = new EventEmitter();
const hits = [];
const fn = (v) => hits.push(v);
e.on('dup', fn);
e.on('dup', fn);
console.log(e.listenerCount('dup'));
e.emit('dup', 'x');
console.log(hits.length + ':' + hits.join(','));
