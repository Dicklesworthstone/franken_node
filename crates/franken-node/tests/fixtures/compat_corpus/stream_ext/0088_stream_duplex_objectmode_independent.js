const { Duplex } = require('stream');
const inbound = [];
const outbound = [{ tag: 'a' }, { tag: 'b' }];
let idx = 0;
const d = new Duplex({
  objectMode: true,
  read() {
    this.push(idx < outbound.length ? outbound[idx++] : null);
  },
  write(obj, enc, cb) {
    inbound.push(obj.n * 10);
    cb();
  },
});
const received = [];
let done = 0;
function report() {
  if (++done === 2) {
    console.log('in:' + inbound.join(','));
    console.log('out:' + received.map((o) => o.tag).join(','));
  }
}
d.on('data', (o) => received.push(o));
d.on('end', report);
d.on('finish', report);
d.write({ n: 2 });
d.end({ n: 5 });
