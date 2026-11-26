const cp = require('child_process');
const r = cp.spawnSync('sh', ['-c', 'printf out; printf err >&2'], { stdio: 'ignore' });
console.log('stdout-null:' + (r.stdout === null));
console.log('stderr-null:' + (r.stderr === null));
console.log('output-all-null:' + (r.output[0] === null && r.output[1] === null && r.output[2] === null));
console.log('status:' + r.status);
