const {EventEmitter} = require('events');
const e = new EventEmitter();
e.once('newListener', (name) => {
  console.log('meta:' + String(name) + ':' + e.listenerCount(name));
});
e.on('data', () => {});
console.log('count-after:' + e.listenerCount('data'));
