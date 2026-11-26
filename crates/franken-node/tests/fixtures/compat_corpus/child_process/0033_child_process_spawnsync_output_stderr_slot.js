const cp = require('child_process');
const r = cp.spawnSync('sh', ['-c', 'printf o1; printf e2 >&2'], { encoding: 'utf8' });
console.log('out0-null:' + (r.output[0] === null));
console.log('out1:' + r.output[1]);
console.log('out2-eq-stderr:' + (r.output[2] === r.stderr));
console.log('out2:' + r.output[2]);
