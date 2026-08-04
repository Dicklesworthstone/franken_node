const {Readable} = require('stream');
(async () => {
  const r = Readable.from(['i1', 'i2', 'i3']);
  const out = [];
  for await (const c of r) out.push(String(c));
  console.log(out.join('>'));
})();
