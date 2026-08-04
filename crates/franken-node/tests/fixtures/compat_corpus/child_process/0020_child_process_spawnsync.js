const cp = require('child_process');
const r = cp.spawnSync('echo', ['dropped'], { stdio: 'ignore' });
console.log('stdout-null:' + (r.stdout === null));
console.log('stderr-null:' + (r.stderr === null));
console.log('status:' + r.status);
