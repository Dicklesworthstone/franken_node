const { Writable } = require('stream');
const { finished } = require('stream/promises');
(async () => {
  const w = new Writable({ write(c, e, cb) { cb(); } });
  w.on('error', () => {});
  const done = finished(w);
  w.destroy(new Error('sink-failed'));
  try {
    await done;
    console.log('no-throw');
  } catch (err) {
    console.log('rejected:' + err.message);
  }
})();
