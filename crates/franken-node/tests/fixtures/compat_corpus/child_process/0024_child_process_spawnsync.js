const cp = require('child_process');
const r = cp.spawnSync('sh', ['-c', 'echo err-msg >&2']);
console.log('stderr:' + r.stderr.toString().trim());
console.log('stdout-empty:' + (r.stdout.toString().length === 0));
console.log('status:' + r.status);
