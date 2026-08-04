const cp = require('child_process');
const r = cp.spawnSync('true', []);
console.log('status:' + r.status);
console.log('has-error:' + (r.error !== undefined));
