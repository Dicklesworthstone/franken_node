const {EventEmitter} = require('events');
const e = new EventEmitter();
const sym = Symbol('channel');
const seen = [];
e.on(sym, (v) => seen.push(v));
console.log(e.listenerCount(sym));
console.log(e.eventNames().length + ':' + (e.eventNames()[0] === sym));
console.log(e.emit(sym, 'hello'));
console.log(seen.join(','));
