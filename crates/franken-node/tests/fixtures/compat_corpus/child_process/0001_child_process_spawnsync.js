const cp = require('child_process');
const r = cp.spawnSync('echo', ['hello-corpus']);
console.log('stdout:' + r.stdout.toString().trim());
console.log('status:' + r.status);
