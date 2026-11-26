const {on, EventEmitter} = require('events');
const e = new EventEmitter();
(async () => {
  const iter = on(e, 'buf');
  e.emit('buf', 'first');
  e.emit('buf', 'second');
  const r1 = await iter.next();
  const r2 = await iter.next();
  await iter.return();
  console.log(r1.done + ':' + r1.value[0]);
  console.log(r2.done + ':' + r2.value[0]);
  console.log('remaining:' + e.listenerCount('buf'));
})();
