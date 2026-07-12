const cp = require('child_process');
const r = cp.spawnSync('definitely-not-a-real-binary-batch-e', []);
console.log('is-error:' + (r.error instanceof Error));
console.log('code:' + r.error.code);
console.log('no-throw:true');
