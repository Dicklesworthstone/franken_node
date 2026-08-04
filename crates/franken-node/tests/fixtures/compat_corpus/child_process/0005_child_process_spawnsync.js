const cp = require('child_process');
const r = cp.spawnSync('echo', ['encoded-out'], { encoding: 'utf8' });
console.log('type:' + typeof r.stdout);
console.log('val:' + r.stdout.trim());
