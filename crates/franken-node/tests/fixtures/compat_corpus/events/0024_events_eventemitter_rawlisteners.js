const {EventEmitter} = require('events');
const e = new EventEmitter();
const fn = () => {};
e.once('w', fn);
const raw = e.rawListeners('w');
console.log(raw.length);
console.log(raw[0].listener === fn);
console.log(e.listeners('w')[0] === fn);
