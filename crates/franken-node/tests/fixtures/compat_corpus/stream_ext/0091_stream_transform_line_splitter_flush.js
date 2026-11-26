const { Transform } = require('stream');
let carry = '';
const lineSplitter = new Transform({
  readableObjectMode: true,
  transform(chunk, enc, cb) {
    const parts = (carry + chunk.toString('utf8')).split('\n');
    carry = parts.pop();
    for (const line of parts) this.push(line);
    cb();
  },
  flush(cb) {
    if (carry.length > 0) this.push(carry);
    cb();
  },
});
const lines = [];
lineSplitter.on('data', (l) => lines.push(l));
lineSplitter.on('end', () => console.log(JSON.stringify(lines)));
lineSplitter.write('fir');
lineSplitter.write('st\nsec');
lineSplitter.end('ond\nlast-no-nl');
