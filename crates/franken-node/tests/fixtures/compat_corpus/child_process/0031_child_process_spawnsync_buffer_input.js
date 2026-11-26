const cp = require('child_process');
const payload = Buffer.from([0x00, 0x01, 0x0a, 0x7f, 0x80, 0xfe, 0xff]);
const r = cp.spawnSync('cat', [], { input: payload });
console.log('is-buf:' + Buffer.isBuffer(r.stdout));
console.log('hex:' + r.stdout.toString('hex'));
console.log('status:' + r.status);
