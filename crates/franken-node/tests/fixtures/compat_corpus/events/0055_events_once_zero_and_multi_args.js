const {once, EventEmitter} = require('events');
const e = new EventEmitter();
(async () => {
  const p0 = once(e, 'empty');
  setImmediate(() => e.emit('empty'));
  const a0 = await p0;
  console.log('empty:' + Array.isArray(a0) + ':' + a0.length);

  const p3 = once(e, 'triple');
  setImmediate(() => e.emit('triple', 'a', 2, false));
  const a3 = await p3;
  console.log('triple:' + a3.length + ':' + a3.join('|'));
})();
