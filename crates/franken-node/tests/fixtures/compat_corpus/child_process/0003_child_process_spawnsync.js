const cp = require('child_process');
const r = cp.spawnSync('false', []);
console.log('status:' + r.status);
console.log('no-throw:true');
