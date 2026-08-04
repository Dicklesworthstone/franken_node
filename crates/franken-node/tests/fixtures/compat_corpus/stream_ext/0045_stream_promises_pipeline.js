const {promises, Readable, Writable} = require('stream');
(async () => {
  const out = [];
  const w = new Writable({write(c, e, cb) { out.push(c.toString()); cb(); }});
  await promises.pipeline(Readable.from(['pp1', 'pp2']), w);
  console.log('done:' + out.join(','));
})();
