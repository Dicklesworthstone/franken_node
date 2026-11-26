const { Readable, Writable } = require('stream');
const { finished } = require('stream/promises');
(async () => {
  const r = Readable.from(['x', 'y']);
  const seen = [];
  r.on('data', (c) => seen.push(c));
  await finished(r);

  const written = [];
  const w = new Writable({ write(c, e, cb) { written.push(c.toString('utf8')); cb(); } });
  w.write('p');
  w.end('q');
  await finished(w);

  console.log('r:' + seen.join(','));
  console.log('w:' + written.join(','));
})();
