const cp = require('child_process');
const r = cp.spawnSync('sh', ['-c', 'exit 7']);
console.log('status:' + r.status);
console.log('signal-null:' + (r.signal === null));
