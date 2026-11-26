const { Writable } = require('stream');
const log = [];
const w = new Writable({
  write(chunk, enc, cb) {
    const s = chunk.toString('utf8');
    process.nextTick(() => {
      log.push('w:' + s);
      cb();
    });
  },
});
w.write('1', () => log.push('cb:1'));
w.write('2', () => log.push('cb:2'));
w.write('3', () => log.push('cb:3'));
w.end(() => {
  log.push('end');
  console.log(log.join('|'));
});
