const {EventEmitter} = require('events');
const e = new EventEmitter();
const fn = () => {};
e.on('newListener', (name, listener) => {
  console.log('new:' + String(name) + ':' + (listener === fn) + ':' + e.listenerCount(name));
});
e.once('boot', fn);
console.log('after:' + e.listenerCount('boot'));
