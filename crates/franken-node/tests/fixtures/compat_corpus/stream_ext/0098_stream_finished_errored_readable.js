const { Readable, finished } = require('stream');
const r = new Readable({ read() {} });
r.on('error', () => {});
finished(r, (err) => {
  console.log('err:' + (err ? err.message : 'none'));
});
r.destroy(new Error('read-broken'));
