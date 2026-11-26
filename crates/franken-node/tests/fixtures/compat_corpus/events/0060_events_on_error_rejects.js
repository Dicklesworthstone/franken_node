const {on, EventEmitter} = require('events');
const e = new EventEmitter();
(async () => {
  const iter = on(e, 'msg');
  setImmediate(() => e.emit('error', new Error('stream-fail')));
  try {
    await iter.next();
    console.log('unexpected');
  } catch (err) {
    console.log('caught:' + err.message);
  }
  console.log('remaining:' + e.listenerCount('msg'));
})();
