const cp = require('child_process');
const out = cp.execSync('cat', { input: Buffer.from('exec-stdin-buf') });
console.log('is-buf:' + Buffer.isBuffer(out));
console.log('out:' + out.toString('utf8'));
