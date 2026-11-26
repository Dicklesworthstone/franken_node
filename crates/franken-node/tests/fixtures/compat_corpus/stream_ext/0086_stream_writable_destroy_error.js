const { Writable } = require('stream');
const events = [];
const w = new Writable({ write(c, e, cb) { cb(); } });
w.on('finish', () => events.push('finish'));
w.on('error', (err) => events.push('error:' + err.message));
w.on('close', () => {
  events.push('close');
  console.log('destroyed:' + w.destroyed);
  console.log(events.join('|'));
});
w.destroy(new Error('write-abort'));
