const cp = require('child_process');
const r = cp.spawnSync('cat', [], { input: 'piped-through-stdin' });
console.log('out:' + r.stdout.toString());
console.log('status:' + r.status);
