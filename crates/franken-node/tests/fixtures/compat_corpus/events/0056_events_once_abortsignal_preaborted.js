const {once, EventEmitter} = require('events');
const e = new EventEmitter();
(async () => {
  const ac = new AbortController();
  ac.abort();
  try {
    await once(e, 'never', { signal: ac.signal });
    console.log('unexpected-resolve');
  } catch (err) {
    console.log('name:' + err.name);
    console.log('code:' + err.code);
  }
  console.log('listeners:' + e.listenerCount('never') + ',' + e.listenerCount('error'));
})();
