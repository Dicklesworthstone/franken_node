const { Transform } = require('stream');
const expander = new Transform({
  objectMode: true,
  transform(chunk, enc, cb) {
    for (const part of chunk.split(',')) {
      this.push(part.trim());
    }
    cb();
  },
});
const out = [];
expander.on('data', (c) => out.push(c));
expander.on('end', () => console.log(out.join('|')));
expander.write('a, b');
expander.end('c, d, e');
