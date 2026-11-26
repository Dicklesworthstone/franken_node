const cp = require('child_process');
const r = cp.spawnSync('printf A && false || printf B', [], { shell: true, encoding: 'utf8' });
console.log('out:' + r.stdout);
console.log('status:' + r.status);
