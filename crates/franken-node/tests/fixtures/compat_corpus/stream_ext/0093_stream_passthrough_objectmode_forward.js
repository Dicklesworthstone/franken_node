const { PassThrough } = require('stream');
const pt = new PassThrough({ objectMode: true });
const o1 = { id: 1, name: 'alpha' };
const o2 = { id: 2, name: 'beta' };
const out = [];
pt.on('data', (item) => out.push(item));
pt.on('end', () => {
  console.log(out.length, out[0] === o1, out[1] === o2);
  console.log(out.map((o) => `${o.id}:${o.name}`).join(','));
});
pt.write(o1);
pt.end(o2);
