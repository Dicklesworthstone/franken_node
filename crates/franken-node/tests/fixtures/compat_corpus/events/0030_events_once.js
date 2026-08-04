const {once, EventEmitter} = require('events');
const e = new EventEmitter();
(async () => {
  const p = once(e, 'never');
  setImmediate(() => e.emit('error', new Error('bad')));
  try { await p; console.log('resolved'); }
  catch (err) { console.log('rejected:' + err.message); }
})();
