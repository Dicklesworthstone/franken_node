const {EventEmitter} = require('events');
const e = new EventEmitter();
const fn = () => console.log('once-ran');
e.on('removeListener', (name, listener) => {
  console.log('meta-rm:' + String(name) + ':' + (listener === fn) + ':' + e.listenerCount(name));
});
e.once('ready', fn);
e.emit('ready');
