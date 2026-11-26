const cp = require('child_process');
const fs = require('fs');
fs.mkdirSync('cp_cwd_0046', { recursive: true });
cp.exec(
  'printf "%s:%s" "$BATCH_E_VAR" "${PWD##*/}"',
  { env: { BATCH_E_VAR: 'ev46' }, cwd: 'cp_cwd_0046' },
  (err, stdout) => {
    console.log('err-null:' + (err === null));
    console.log('out:' + stdout);
    fs.rmSync('cp_cwd_0046', { recursive: true, force: true });
  }
);
