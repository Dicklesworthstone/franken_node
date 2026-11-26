const {EventEmitter} = require('events');
const e = new EventEmitter();
const order = [];
const a = () => {};
const b = () => {};
const c = () => {};
e.on('removeListener', (name, fn) => {
  if (name === 'x') order.push(fn === a ? 'a' : fn === b ? 'b' : 'c');
});
e.on('x', a);
e.on('x', b);
e.on('x', c);
e.removeAllListeners('x');
console.log(order.join(','));
console.log(e.listenerCount('x'));
