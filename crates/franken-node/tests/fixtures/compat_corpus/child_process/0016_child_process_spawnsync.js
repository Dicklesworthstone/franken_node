const cp = require('child_process');
const r = cp.spawnSync('echo shell-and-pipe | cat', [], { shell: true });
console.log('out:' + r.stdout.toString().trim());
console.log('status:' + r.status);
