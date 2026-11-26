const cp = require('child_process');
cp.execFile(
  'sh',
  ['-c', 'printf "%s:%s" "$1" "$BATCH_E_VAR"', '_', 'arg1'],
  { env: { BATCH_E_VAR: 'ef47' } },
  (err, stdout, stderr) => {
    console.log('err-null:' + (err === null));
    console.log('stdout:' + stdout);
    console.log('stderr-empty:' + (stderr === ''));
  }
);
