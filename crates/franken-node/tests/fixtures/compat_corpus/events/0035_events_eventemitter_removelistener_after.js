const {EventEmitter} = require('events');
const e = new EventEmitter();
const a = () => {};
const b = () => {};
e.on('removeListener', (name, listener) => {
  console.log('removed:' + String(name) + ':' + (listener === a) + ':remaining=' + e.listenerCount(name));
});
e.on('job', a);
e.on('job', b);
e.removeListener('job', a);
console.log('final:' + e.listenerCount('job'));
