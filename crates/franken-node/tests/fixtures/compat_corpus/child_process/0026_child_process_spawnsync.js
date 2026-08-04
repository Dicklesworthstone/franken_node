const cp = require('child_process');
const r = cp.spawnSync('true', []);
console.log('signal-null:' + (r.signal === null));
console.log('pid-num:' + (typeof r.pid === 'number'));
console.log('status:' + r.status);
