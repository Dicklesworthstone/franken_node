const cp = require('child_process');
const out = cp.execSync('printf "%s" "$BATCH_E_VAR" | cat', {
  encoding: 'utf8',
  env: { BATCH_E_VAR: 'pipe-env-ok' },
});
console.log('type:' + typeof out);
console.log('out:' + out);
