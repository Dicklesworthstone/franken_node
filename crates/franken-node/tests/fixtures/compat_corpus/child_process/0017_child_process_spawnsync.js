const cp = require('child_process');
const r = cp.spawnSync('sh', ['-c', 'echo "$BATCH_E_VAR"'], {
  env: { BATCH_E_VAR: 'set-by-test' },
});
console.log('env-val:' + r.stdout.toString().trim());
console.log('status:' + r.status);
