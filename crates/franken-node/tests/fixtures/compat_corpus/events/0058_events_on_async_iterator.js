const {on, EventEmitter} = require('events');
const e = new EventEmitter();
(async () => {
  const iter = on(e, 'item');
  setImmediate(() => {
    e.emit('item', 'a', 1);
    e.emit('item', 'b', 2);
    e.emit('item', 'c', 3);
  });
  const got = [];
  for await (const args of iter) {
    got.push(args.join(':'));
    if (got.length === 2) break;
  }
  console.log(got.join(','));
  console.log('after-break:' + e.listenerCount('item'));
})();
