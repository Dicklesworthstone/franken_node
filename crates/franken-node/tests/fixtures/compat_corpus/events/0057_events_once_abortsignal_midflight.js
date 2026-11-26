const {once, EventEmitter} = require('events');
const e = new EventEmitter();
(async () => {
  const ac = new AbortController();
  const p = once(e, 'late', { signal: ac.signal });
  setTimeout(() => ac.abort(), 10);
  try {
    await p;
    console.log('unexpected-resolve');
  } catch (err) {
    console.log('name:' + err.name);
    console.log('code:' + err.code);
  }
  console.log('listeners:' + e.listenerCount('late') + ',' + e.listenerCount('error'));
})();
