const { Readable, Writable } = require('stream');
const src = Readable.from(['p1-', 'p2-', 'p3']);
const out1 = [];
const out2 = [];
let finishedCount = 0;
function done() {
  if (++finishedCount === 2) {
    console.log('w1:' + out1.join(''));
    console.log('w2:' + out2.join(''));
  }
}
const w1 = new Writable({ write(c, e, cb) { out1.push(c.toString('utf8')); cb(); } });
const w2 = new Writable({ write(c, e, cb) { out2.push(c.toString('utf8')); cb(); } });
w1.on('finish', done);
w2.on('finish', done);
src.pipe(w1);
src.pipe(w2);
