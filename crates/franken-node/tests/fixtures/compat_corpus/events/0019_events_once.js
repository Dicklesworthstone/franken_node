const {once, EventEmitter} = require('events');
const e = new EventEmitter();
(async () => {
  const p = once(e, 'ready');
  setImmediate(() => e.emit('ready', 'val', 42));
  const args = await p;
  console.log(args.length + ':' + args[0] + ':' + args[1]);
})();
