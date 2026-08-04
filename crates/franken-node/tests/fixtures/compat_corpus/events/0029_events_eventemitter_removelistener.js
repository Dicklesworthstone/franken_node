const {EventEmitter} = require('events');
const e = new EventEmitter();
const fn = () => {};
e.on('removeListener', (name, l) => console.log('removed:' + String(name) + ':' + (l === fn)));
e.on('gone', fn);
e.off('gone', fn);
