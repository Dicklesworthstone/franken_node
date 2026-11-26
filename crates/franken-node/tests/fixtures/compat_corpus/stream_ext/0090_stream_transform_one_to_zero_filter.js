const { Transform } = require('stream');
const onlyEvens = new Transform({
  objectMode: true,
  transform(n, enc, cb) {
    if (n % 2 === 0) this.push(n);
    cb();
  },
});
const out = [];
onlyEvens.on('data', (n) => out.push(n));
onlyEvens.on('end', () => console.log(out.join(',')));
for (const n of [1, 2, 3, 4, 5, 6, 7]) onlyEvens.write(n);
onlyEvens.end();
