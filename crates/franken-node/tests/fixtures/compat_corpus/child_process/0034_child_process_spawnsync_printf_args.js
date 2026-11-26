const cp = require('child_process');
const r = cp.spawnSync('printf', ['%s=%d', 'count', '42'], { encoding: 'utf8' });
console.log('out:' + r.stdout);
console.log('len:' + r.stdout.length);
console.log('status:' + r.status);
