const { Readable } = require('stream');
const items = ['c1', 'c2', 'c3', 'c4'];
let idx = 0;
const r = new Readable({
  encoding: 'utf8',
  read() {
    if (idx < items.length) this.push(items[idx++]);
    else this.push(null);
  },
});
const log = [];
r.on('data', (chunk) => {
  log.push('data:' + chunk);
  if (chunk === 'c1' || chunk === 'c3') {
    r.pause();
    log.push('paused:' + r.isPaused());
    process.nextTick(() => {
      r.resume();
      log.push('resumed:' + r.isPaused());
    });
  }
});
r.on('end', () => {
  log.push('end');
  console.log(log.join('|'));
});
